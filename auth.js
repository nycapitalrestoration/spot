// ------------------------------
// PKCE AUTH SYSTEM (required by Spotify in 2025+)
// ------------------------------

// Generate random string
function generateRandomString(len) {
    let text = "";
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (let i = 0; i < len; i++) text += chars.charAt(Math.floor(Math.random() * chars.length));
    return text;
}

// SHA256 encoder
async function sha256(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    return crypto.subtle.digest("SHA-256", data);
}

// Base64 URL encode
function base64url(buffer) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

// Start login
async function spotifyLogin() {
    const codeVerifier = generateRandomString(64);
    localStorage.setItem("code_verifier", codeVerifier);

    const digest = await sha256(codeVerifier);
    const codeChallenge = base64url(digest);

    const url =
        "https://accounts.spotify.com/authorize" +
        `?response_type=code` +
        `&client_id=${encodeURIComponent(SPOTIFY_CLIENT_ID)}` +
        `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
        `&code_challenge_method=S256` +
        `&code_challenge=${codeChallenge}` +
        `&scope=${encodeURIComponent(SPOTIFY_SCOPES)}` +
        `&show_dialog=true`; // FORCE permissions every time

    window.location = url;
}

// Exchange authorization code for token
async function requestAccessToken(code) {
    const codeVerifier = localStorage.getItem("code_verifier");

    const body = new URLSearchParams({
        client_id: SPOTIFY_CLIENT_ID,
        grant_type: "authorization_code",
        code: code,
        redirect_uri: REDIRECT_URI,
        code_verifier: codeVerifier
    });

    const response = await fetch("https://accounts.spotify.com/api/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body
    });

    const data = await response.json();
    if (data.error) {
        alert("TOKEN ERROR: " + JSON.stringify(data));
        throw new Error("Token exchange failed");
    }

    localStorage.setItem("spotify_access_token", data.access_token);
    localStorage.setItem("spotify_refresh_token", data.refresh_token);
    localStorage.setItem("token_timestamp", Date.now().toString());

    return data.access_token;
}

// Refresh access token
async function refreshToken() {
    const refresh = localStorage.getItem("spotify_refresh_token");
    if (!refresh) return null;

    const body = new URLSearchParams({
        client_id: SPOTIFY_CLIENT_ID,
        grant_type: "refresh_token",
        refresh_token: refresh
    });

    const response = await fetch("https://accounts.spotify.com/api/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body
    });

    const data = await response.json();
    if (data.access_token) {
        localStorage.setItem("spotify_access_token", data.access_token);
        localStorage.setItem("token_timestamp", Date.now().toString());
        return data.access_token;
    }

    return null;
}

// Get valid access token
async function getAccessToken() {
    let token = localStorage.getItem("spotify_access_token");

    // Token expired (1 hour)
    const timestamp = parseInt(localStorage.getItem("token_timestamp") || "0");
    if (Date.now() - timestamp > 3500000) {
        token = await refreshToken();
    }

    return token;
}
