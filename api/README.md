# API container (FastAPI)

A REST API for the end-to-end encrypted storage. It manages accounts and authentication and asks
cryptdaemon (Unix socket) to create the user's SFTPGo account. It never sees the password or any
volume key: the "password" it receives is a login key derived by the client (docs/design-e2ee.md).

---

## Tech stack

- **FastAPI** – REST API framework
- **SQLAlchemy** – ORM, MariaDB in production / SQLite in development
- **argon2-cffi** – password hashing (Argon2id; legacy bcrypt hashes are still verified)
- **PyJWT** – JWT tokens
- **cryptography** – TOTP secret encryption, escrow seal check
- **slowapi** – rate limiting

---

## File structure

```
api/
├── main.py             # All REST routes, rate limiting
├── database.py         # SQLAlchemy engine + session
├── models.py           # User model
├── schemas.py          # Pydantic validation
├── auth.py             # Argon2id + JWT
├── totp.py             # Two-factor (TOTP)
├── ssh_keys.py         # SSH public key checks
├── audit.py            # Audit log for security events (DB + logger)
├── migrations/         # SQL migrations for the production database
├── socket_client.py    # Communication with the daemon (HMAC-signed)
├── Dockerfile
├── requirements.txt
└── README.md
```

---

## API routes

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/health` | Liveness |
| GET | `/server-info` | Public: SFTP host/port, recovery policy, escrow public key |
| POST | `/auth/register` | Register (login key, SSH public key); no key or recovery code is created here |
| POST | `/auth/verify-email` | Confirm the e-mail address |
| POST | `/auth/login` | Login → JWT + refresh token |
| POST | `/auth/refresh` | New access token with a refresh token (rotation, reuse detection) |
| POST | `/auth/recover-e2ee` | Set a new login key with a recovery proof (and a TOTP code if the account has one) |
| POST | `/auth/cancel-change` | Cancel a waiting SSH key change or deletion with the link from the e-mail |
| GET | `/users/me` | User information |
| PUT | `/users/me/ssh-key` | Set the SSH public key; replacing one waits `CHANGE_DELAY_HOURS` |
| GET, DELETE | `/users/me/pending-changes[/{id}]` | Waiting SSH key changes and deletions; cancel one |
| POST | `/users/me/password` | Change the login key (the client re-wraps the volume) |
| PUT | `/users/me/recovery-verifier` | Store the recovery verifier |
| PUT, GET | `/users/me/escrow` | Store / read back the escrow blob |
| POST | `/users/me/totp/setup`, `/enable`, `/disable` | Two-factor enrolment (enable needs the code sent by e-mail) |
| GET | `/storage/e2ee` | Create/confirm the SFTPGo user; returns host, port, user, usage |
| GET | `/storage/usage` | Disk usage in bytes |
| DELETE | `/storage` | Delete the account and data permanently after `CHANGE_DELAY_HOURS` |

With `REQUIRED_FACTORS=password,totp` (the default) an account without an authenticator app gets 403
`SECOND_FACTOR_SETUP_REQUIRED` everywhere except `/users/me`, the TOTP setup and the pending changes.
Replacing the SSH key, deleting the account and changing the password ask for the password and, when the
account has two-factor, a code; a login that passed two-factor in the last 5 minutes counts as one.

The mount, umount, status and recovery-code routes of the removed server-side mode no longer exist.

---

## Database structure

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| username | string(32) | Unique, `[a-zA-Z0-9_]` |
| email | string | Unique |
| password_hash | string | Argon2id (legacy: bcrypt) |
| recovery_encrypted_master_key | string | Slow hash of the recovery proof (the recovery verifier; old column name kept) |
| escrow_blob | text | Master key sealed to the operator's escrow key (opaque) |
| ssh_public_key | text | ed25519/rsa/ecdsa |
| storage_created | bool | The SFTPGo user exists |
| quota_bytes | int | Default: 10 GB |
| created_at | datetime | |
| last_login | datetime | |
| is_active | bool | |
| email_verified | bool | |

**refresh_tokens** – refresh token rotation and theft detection

**security_events** – audit log (login, password change, token reuse, ...)

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite:///./cryptdb.sqlite` | `mysql+pymysql://user:pw@host/db` in production |
| `JWT_SECRET_KEY` | *required* | Set to a long random string |
| `JWT_EXPIRE_MINUTES` | `60` | Token lifetime |
| `DAEMON_AUTH_KEY` | *required* | HMAC key for the daemon socket (hex) |
| `SERVER_HOST` | `your-server.example.com` | Hostname clients use for SFTP |
| `CORS_ORIGINS` | `http://localhost` | Allowed CORS origins |
| `SMTP_HOST` | `` | SMTP server (empty = dev mode, logs the link) |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USER` | `` | SMTP username |
| `SMTP_PASSWORD` | `` | SMTP password |
| `SMTP_FROM` | `` | Sender address |
| `REQUIRE_EMAIL_VERIFICATION` | `true` | Require e-mail verification at registration |
| `JWT_REFRESH_EXPIRE_DAYS` | `7` | Refresh token lifetime |
| `SFTP_PORT` | `2222` | Port of the SFTP service reported to clients |
| `RECOVERY_POLICY` | `user` | `user`, `escrow` or `both`; the last two need `ESCROW_PUBLIC_KEY` (`scripts/escrow.py keygen`) |
| `TOTP_ENCRYPTION_KEY` | – | 64 hex characters. Enables two-factor (TOTP); keep it outside the database. Required with `REQUIRED_FACTORS=password,totp`, otherwise 503 from the TOTP endpoints if unset |
| `REQUIRED_FACTORS` | `password,totp` | `password,totp`: an authenticator app is mandatory. `password`: optional (only for tests or closed networks) |
| `CHANGE_DELAY_HOURS` | `24` | How long a new SSH key or an account deletion waits; the owner is e-mailed a cancel link at once |
| `CHANGE_WORKER_INTERVAL` | `300` | Seconds between runs of the thread that applies due changes (0 = off) |

---

Test with `tests/` (pytest) and `scripts/e2ee_integration.sh` (real API, sshd, sshfs, gocryptfs).
