<?php
// auth.php - Session handling helpers

require_once __DIR__ . '/config.php';

// Nonce for the page's inline <script> blocks (one per request)
function csp_nonce(): string {
    static $nonce = null;
    if ($nonce === null) {
        $nonce = base64_encode(random_bytes(16));
    }
    return $nonce;
}

function send_security_headers(): void {
    // Scripts only with this request's nonce, so injected markup cannot run code.
    // Inline styles are still used throughout the pages; the fonts are served from this server (assets/fonts).
    header("Content-Security-Policy: default-src 'none'; "
         . "script-src 'nonce-" . csp_nonce() . "'" . " 'self' 'wasm-unsafe-eval'" . "; "
         . "style-src 'self' 'unsafe-inline'; "
         . "font-src 'self'; img-src 'self' data:; "
         . "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: same-origin');
    header('Cache-Control: no-store');
}

// --- CSRF: every state-changing POST must carry the session's token ---

function csrf_token(): string {
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function csrf_field(): string {
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(csrf_token(), ENT_QUOTES) . '">';
}

function csrf_require(): void {
    $sent = $_POST['csrf_token'] ?? '';
    if (!is_string($sent) || empty($_SESSION['csrf']) || !hash_equals($_SESSION['csrf'], $sent)) {
        http_response_code(403);
        exit('Invalid or missing security token. Go back, reload the page and try again.');
    }
}

function session_start_secure(): void {
    send_security_headers();
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', 1);
    ini_set('session.cookie_samesite', 'Strict');
    ini_set('session.gc_maxlifetime', SESSION_LIFETIME);
    session_name(SESSION_NAME);
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
}

function is_logged_in(): bool {
    return !empty($_SESSION['jwt_token']) && !empty($_SESSION['username']);
}

function require_login(): void {
    if (!is_logged_in()) {
        header('Location: index.php');
        exit;
    }
}

function save_session(string $token, string $username): void {
    session_regenerate_id(true);
    unset($_SESSION['csrf']);          // new token for the new session
    $_SESSION['jwt_token'] = $token;
    $_SESSION['username']  = $username;
}

function clear_session(): void {
    $_SESSION = [];
    session_destroy();
}

function get_token(): string {
    return $_SESSION['jwt_token'] ?? '';
}

function get_username(): string {
    return $_SESSION['username'] ?? '';
}

// --- The server must never receive the real password ---

// The browser sends HKDF output (64 hex characters) instead of the password. If it did not (script
// blocked, old browser, tampered form), refuse here instead of forwarding the real password to the API.
function login_key_ok(string $v): bool {
    return preg_match('/^[0-9a-f]{64}$/', $v) === 1;
}

const LOGIN_KEY_ERROR = 'Your browser could not prepare the password securely. Allow scripts for this page, or use a current browser.';

// Loads the derivation script (after the page's own scripts, so a cancelled confirm() is seen first).
function derive_script_tag(): string {
    $n = htmlspecialchars(csp_nonce(), ENT_QUOTES);
    return '<script nonce="' . $n . '" src="assets/argon2.umd.min.js"></script>'
         . '<script nonce="' . $n . '" src="assets/derive.js"></script>';
}

// --- Passkeys (assets/passkey.js) ---

// The server's WebAuthn options as inert JSON for passkey.js; mode is "get" (sign in) or "create" (add).
function passkey_options_tag(array $options, string $mode): string {
    $json = json_encode($options, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
    return '<script type="application/json" id="passkey-options" data-mode="' . htmlspecialchars($mode, ENT_QUOTES) . '">'
         . $json . '</script>';
}

function passkey_script_tag(): string {
    return '<script nonce="' . htmlspecialchars(csp_nonce(), ENT_QUOTES) . '" src="assets/passkey.js"></script>';
}

// The browser's answer as posted by passkey.js, or null
function posted_credential(): ?array {
    $c = json_decode($_POST['credential'] ?? '', true);
    return is_array($c) && strlen($_POST['credential'] ?? '') <= 16384 ? $c : null;
}
