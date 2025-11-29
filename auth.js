// auth.js
// Handles Spotify PKCE login entirely in-browser
export function base64UrlEncode(str) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(str)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

export async function sha256(plain) {
    const encoder = new TextEncoder();
    const data = encoder.encode(plain);
    const hash = await crypto.subtle.digest("SHA-256", data);
    return hash;
}

export function generateRandomString(length) {
    let text = "";
    const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (let i = 0; i < length; i++) {
        text += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return text;
}

export function storeToken(token) {
    localStorage.setItem("spotify_token", token);
}

export function getStoredToken() {
    return localStorage.getItem("spotify_token");
}

export async function startSpotifyLogin(conf) {
    const state = generateRandomString(16);
    const codeVerifier = generateRandomString(128);
    localStorage.setItem("spotify_code_verifier", codeVerifier);
    localStorage.setItem("spotify_state", state);

    const codeChallengeBuffer = await sha256(codeVerifier);
    const codeChallenge = base64UrlEncode(codeChallengeBuffer);

    const params = new URLSearchParams({
        response_type: "code",
        client_id: conf.client_id,
        scope: "playlist-read-private playlist-modify-private playlist-modify-public user-library-read",
        redirect_uri: conf.redirect_uri,
        state: state,
        code_challenge_method: "S256",
        code_challenge: codeChallenge
    });

    window.location = "https://accounts.spotify.com/authorize?" + params.toString();
}

export async function finishSpotifyLogin(conf) {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get("code");
    const state = urlParams.get("state");
    const storedState = localStorage.getItem("spotify_state");

    if (!code || !state || state !== storedState) return;

    const codeVerifier = localStorage.getItem("spotify_code_verifier");

    const body = new URLSearchParams({
        grant_type: "authorization_code",
        code: code,
        redirect_uri: conf.redirect_uri,
        client_id: conf.client_id,
        code_verifier: codeVerifier
    });

    const resp = await fetch("https://accounts.spotify.com/api/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString()
    });

    const data = await resp.json();
    if (data.access_token) {
        storeToken(data.access_token);
        // Remove code & state from URL
        window.history.replaceState({}, document.title, conf.redirect_uri);
    }
}
