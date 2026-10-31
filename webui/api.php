<?php
// api.php - Thin wrapper around the FastAPI backend.

require_once __DIR__ . '/config.php';

class ApiClient {

    private string $base;
    private ?string $token;

    public function __construct(?string $token = null) {
        $this->base  = rtrim(API_BASE_URL, '/');
        $this->token = $token;
    }

    // --- Auth ---

    public function register(string $username, string $email, string $password): array {
        $body = ['username' => $username, 'email' => $email, 'password' => $password];
        return $this->post('/auth/register', $body);
    }

    // Every sign-in here asks for a web session: it manages the account, never opens the storage,
    // and confirms sensitive actions with a recent sign-in instead of the password
    public function login(string $username, string $password, ?string $totp_code = null): array {
        $body = ['username' => $username, 'password' => $password, 'web' => true];
        if ($totp_code !== null && $totp_code !== '') { $body['totp_code'] = $totp_code; }
        return $this->post('/auth/login', $body);
    }

    // Two-factor authentication (authenticator app)
    public function totp_setup(): array {
        return $this->post('/users/me/totp/setup', []);
    }
    public function totp_enable(string $code, string $email_code): array {
        return $this->post('/users/me/totp/enable', ['code' => $code, 'email_code' => $email_code]);
    }
    public function totp_disable(string $code): array {
        return $this->post('/users/me/totp/disable', ['code' => $code]);
    }

    // Passkeys (WebAuthn): options for the browser and a session that comes back with its answer
    public function passkey_begin(string $username, string $password): array {
        return $this->post('/auth/passkey/begin', ['username' => $username, 'password' => $password]);
    }
    public function passkey_finish(string $session, array $credential): array {
        return $this->post('/auth/passkey/finish', ['session' => $session, 'credential' => $credential, 'web' => true]);
    }
    // Sign-in with the passkey alone, no password
    public function web_passkey_begin(string $username): array {
        return $this->post('/auth/web/passkey/begin', ['username' => $username]);
    }
    public function web_passkey_finish(string $session, array $credential): array {
        return $this->post('/auth/web/passkey/finish', ['session' => $session, 'credential' => $credential]);
    }
    // A sign-in the app handed over (`cryptclient web-login`)
    public function web_ticket_redeem(string $ticket): array {
        return $this->post('/auth/web/ticket/redeem', ['ticket' => $ticket]);
    }
    public function passkeys(): array {
        return $this->get('/users/me/passkeys');
    }
    public function passkey_register_begin(string $totp_code = ''): array {
        $body = [];
        if ($totp_code !== '') { $body['totp_code'] = $totp_code; }
        return $this->post('/users/me/passkeys/register/begin', $body);
    }
    public function passkey_register_finish(string $session, string $name, array $credential): array {
        return $this->post('/users/me/passkeys/register/finish',
                           ['session' => $session, 'name' => $name, 'credential' => $credential]);
    }
    public function passkey_delete(string $id, string $totp_code = ''): array {
        $body = [];
        if ($totp_code !== '') { $body['totp_code'] = $totp_code; }
        return $this->request('DELETE', '/users/me/passkeys/' . rawurlencode($id), $body);
    }

    // --- USB sticks (the server's half of the stick's key) ---

    public function sticks(): array {
        return $this->get('/users/me/sticks');
    }
    public function stick_lock(string $id): array {
        return $this->request('POST', '/users/me/sticks/' . rawurlencode($id) . '/lock', []);
    }
    public function stick_delete(string $id, string $totp_code = ''): array {
        $body = [];
        if ($totp_code !== '') { $body['totp_code'] = $totp_code; }
        return $this->request('DELETE', '/users/me/sticks/' . rawurlencode($id), $body);
    }

    // --- User ---

    public function me(): array {
        return $this->get('/users/me');
    }
    public function escrow(): array {
        return $this->get('/users/me/escrow');
    }

    // --- Storage ---

    public function storage_usage(): array {
        return $this->get('/storage/usage');
    }

    public function refresh_token(string $refresh_token): array {
        return $this->post('/auth/refresh', ['refresh_token' => $refresh_token]);
    }

    public function verify_email(string $token): array {
        return $this->post('/auth/verify-email', ['token' => $token]);
    }

    // The deletion waits on the server; the answer says when it happens.
    public function delete_account(string $totp_code = ''): array {
        $body = [];
        if ($totp_code !== '') { $body['totp_code'] = $totp_code; }
        return $this->request('DELETE', '/storage', $body);
    }

    // Waiting SSH key changes and deletions
    public function pending_changes(): array {
        return $this->get('/users/me/pending-changes');
    }
    public function cancel_pending(string $id): array {
        return $this->request('DELETE', '/users/me/pending-changes/' . rawurlencode($id));
    }
    // With the link from the e-mail, no sign-in
    public function cancel_change(string $token): array {
        return $this->post('/auth/cancel-change', ['token' => $token]);
    }

    // --- HTTP helpers ---

    private function get(string $path): array {
        return $this->request('GET', $path);
    }

    private function post(string $path, array $body): array {
        return $this->request('POST', $path, $body);
    }

    private function put(string $path, array $body): array {
        return $this->request('PUT', $path, $body);
    }

    private function delete(string $path): array {
        return $this->request('DELETE', $path);
    }

    private function request(string $method, string $path, ?array $body = null, int $timeout = 15): array {
        $url = $this->base . $path;

        $headers = ['Content-Type: application/json', 'Accept: application/json'];
        // The API sees this container as its peer; tell it who the real client is
        // (X-Real-IP is set by nginx and overwritten there, so it cannot be spoofed).
        $client_ip = $_SERVER['HTTP_X_REAL_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? '';
        if (filter_var($client_ip, FILTER_VALIDATE_IP)) {
            $headers[] = 'X-Forwarded-For: ' . $client_ip;
        }
        if ($this->token) {
            $headers[] = 'Authorization: Bearer ' . $this->token;
        }

        $opts = [
            'http' => [
                'method'        => $method,
                'header'        => implode("\r\n", $headers),
                'ignore_errors' => true,
                'timeout'       => $timeout,
            ]
        ];

        if ($body !== null) {
            $opts['http']['content'] = json_encode($body === [] ? new stdClass() : $body);   // {} not []
        }

        $ctx      = stream_context_create($opts);
        $raw      = @file_get_contents($url, false, $ctx);
        $response = $raw !== false ? json_decode($raw, true) : null;

        if ($response === null) {
            return ['error' => 'Could not connect to API server.'];
        }

        return $response;
    }
}
