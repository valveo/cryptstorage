# Web UI (PHP)

The user-facing management panel. PHP 8.3 + Apache, no framework.
Talks to the API container directly over HTTP.

---

## Files

```
webui/
├── index.php           # Sign-in (passkey, ticket from the app, password) + registration
├── dashboard.php       # Management panel
├── recover.php         # Points to `cryptclient recover` (only the app can re-wrap the volume)
├── passkey-approve.php # Approves the app's passkey sign-in in the browser
├── cancel.php          # Cancels a waiting change with the link from the e-mail
├── verify-email.php    # E-mail confirmation link
├── api.php             # ApiClient (PHP → FastAPI)
├── auth.php            # Session management, CSRF, security headers (CSP with a nonce)
├── config.php          # API URL, session settings, build version
├── logout.php          # Logout
├── assets/             # derive.js + hash-wasm (login key in the browser), passkey.js
├── Dockerfile
└── README.md               # (the whole stack is started with Ansible: see ../ansible)
```

---

## Login key and what the page shows

`assets/derive.js` turns the password into the login key in the browser (Argon2id in WebAssembly, `assets/argon2.umd.min.js` is hash-wasm 4.12.0, MIT);
the server sees only that key. PHP refuses a login that does not carry a derived key, so the real password cannot reach the API even with scripts
blocked. This protects against an honest server only; see index.php below for the sign-ins without the password. There is no mount, SSH key, password-change or recovery panel: those need the app, because only it can re-wrap the volume.
Check after changing the script: `node assets/derive.test.mjs`.

## Pages

### index.php
Sign-in and registration. The server also serves this page's scripts, so a password typed here is only as
safe as the server. The page therefore signs in without it:
- **Passkey alone**: username, then the passkey (the device must verify the user). API `/auth/web/passkey/*`.
- **From the app**: `cryptclient web-login` signs in as the app does and opens `index.php#ticket=…`; the
  page posts the one-time ticket (two minutes, after `#` so it never reaches server logs) and gets a session. API `/auth/web/ticket/redeem`.
- **Password** (accounts without a passkey): folded away and labelled as trusting the server; the second step
  asks for the passkey or the code.

Every sign-in here gets a **web session** (`"web": true`): no refresh token, no access to the stick secrets,
the storage address, key or password changes or the escrow. A successful sign-in stores the JWT in the PHP
session and redirects to the dashboard.

### dashboard.php
- **Disk usage**, account details, waiting changes (cancel), escrow state
- **Two-factor**, **passkeys**, **USB sticks** (remove a lost one) and **deleting the account**. None of these
  asks for the password: the API accepts a sign-in from the last 10 minutes instead, and the page offers to
  sign in again after that (`REAUTH_REQUIRED`).

---

## Session security

- `cookie_httponly` – JS cannot access the session cookie
- `cookie_secure` – HTTPS only
- `cookie_samesite=Strict` – CSRF protection
- `session_regenerate_id(true)` on login
- The JWT is stored in the session, not directly in a cookie

---

## Starting (whole stack)

```bash
docker compose up -d
```

Starts:
- `webui` → `127.0.0.1:8080` (nginx on the host terminates TLS in front of it)
- `api` → `127.0.0.1:8000` (nginx serves it under `/api/`)
- `sftpgo` → the SFTP port (default 2222), ciphertext only
- `db` → MariaDB 11 (internal)

The Unix socket `/run/cryptdaemon/cryptdaemon.sock` is mounted into the API container.
**The host daemon must be run separately** (systemd service, not as a container).

---

## Environment variables

| Variable | Description |
|----------|-------------|
| `API_BASE_URL` | Where PHP reaches the API (default `http://api:8000`) |
| `SOURCE_URL` | Optional. Where the "Source code" link at the bottom of every page points (default: this repository). If you run a changed version, point it at your source; the AGPL requires offering it to your users |
| `DOWNLOAD_URL` | Optional. Link to the client download page (the playbook sets `/download/` when `client_downloads_src` is set); empty = no link |

Create the secrets with `ansible/generate-secrets.sh`; Ansible generates
docker-compose.yml from a template (`ansible/roles/cryptstack/templates/`).
