# Security Policy

> **Status: pre-release software, not independently audited.**
> CryptStorage handles encryption keys and user data. Do not rely on it for sensitive
> data until it has been reviewed by someone other than its author. This document
> tries to say plainly what the design protects and what it does not.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

- Use GitHub's private vulnerability reporting: **Security → Report a vulnerability**
  on this repository (the maintainer must enable it under
  *Settings → Code security*).
- Security contact e-mail: `security@venomia.fi`.

Please include what you found, how to reproduce it, the affected commit or version,
and the impact you expect. A proof of concept is welcome but not required.

What to expect (the project has one maintainer; these are best-effort targets):

- Acknowledgement within 7 days.
- A fix or mitigation plan within 30 days for high-severity issues.
- Coordinated disclosure: we ask for up to 90 days before public disclosure, and we
  will credit you in the advisory unless you prefer otherwise.

## Supported versions

| Version | Security fixes |
|---|---|
| 0.1.x (pre-release) | the latest 0.1 release and `main` |
| older commits | no |

Before 1.0 a fix may need a new release rather than a patch to an older one. Release notes
([CHANGELOG.md](CHANGELOG.md)) say when an update fixes a security problem.

## What CryptStorage is

Self-hosted **end-to-end encrypted** storage. The client encrypts files in the
[gocryptfs](https://nuetzlich.net/gocryptfs/) format (cppcryptfs on Windows) before anything leaves the
user's machine; the server stores only ciphertext in an [SFTPGo](https://github.com/drakkan/sftpgo) service and never receives the password,
the volume key or any plaintext. The design is in [docs/design-e2ee.md](docs/design-e2ee.md). It is a
prototype and has not been audited.

| Component | Role |
|---|---|
| `api/` | FastAPI service: registration, login, tokens, recovery verifier, escrow blob |
| `cryptdaemon/` | Daemon on the host: creates and removes the SFTPGo users (REST API on the loopback) |
| `webui/` | PHP web interface: account information only; derives the login key in the browser |
| `cryptclient/` | Go client: setup, USB key stick, encryption, SSHFS mount |
| `ansible/` | Deployment (nginx/TLS, Docker for api/webui/db/SFTPGo, firewall, fail2ban, systemd) |

## Cryptographic design (summary for reviewers)

- One password gives two keys on the client: `root = Argon2id(password, salt from the username)`, then
  `AuthKey = HKDF(root, "secdisk/auth/v1")` (sent to the server, which stores an Argon2id hash of it) and
  `VolumePass = HKDF(root, "secdisk/volume/v1")` (the gocryptfs passphrase, never leaves the client). The
  web UI derives the AuthKey in the browser (Argon2id in WebAssembly); PHP refuses anything that is not a derived key.
- The volume master key is random, chosen by the client, and stored only wrapped inside `gocryptfs.conf`
  (scrypt) on the server. Changing the password re-wraps it on the client; data is not re-encrypted.
- The user's SSH private key is kept on the USB stick, encrypted with Argon2id and AES-GCM under the password;
  the decrypted key lives only in memory (an in-process agent). The client pins the server's SSH host key
  and the server's TLS public key, both stored on the stick's file system. The SSH host key comes from the API
  over the pinned TLS connection (`ssh_host_keys` of `GET /storage/e2ee`), so the user is not asked to trust
  it; a key the API does not list is refused. Only a server that does not report its keys falls back to
  trust on first use. When the stick's file system is not mounted nothing is stored anywhere else.
- **Recovery.** At setup the client shows a recovery code (the master key with a checksum) once. The server
  stores only a slow hash of a value derived from it (the recovery verifier) so it can check possession
  without being able to open the volume. The client re-wraps `gocryptfs.conf` itself after reading a canary file
  with the recovered key. Policy `escrow` or `both` additionally stores the master key sealed to the operator's
  escrow public key; with escrow on the operator **can** read everything, and the client says so.
- Login returns a 60-minute JWT (invalidated on password change) and a rotating refresh token (stored hashed
  with a server-side HMAC key, with reuse detection).
- **Second factor.** By default (`REQUIRED_FACTORS=password,totp`) every account needs an authenticator
  app: with the password alone a session reaches only the setup of that app, and turning it on also needs a
  code sent by e-mail, so a password thief cannot enrol their own phone. Replacing the SSH key, deleting the
  account and changing the password ask for the password and a code again (a login with a code in the last
  5 minutes counts). A web UI session has no password to give: it confirms with a sign-in from the last 10
  minutes instead, and the key and password changes are not open to it at all. The recovery code
  replaces the password, not the second factor; replacing the stored recovery verifier e-mails the owner,
  because it makes the old recovery code useless.
- **Passkeys.** In the web UI a passkey (WebAuthn: Face ID, a fingerprint, a phone through a QR code, or a
  FIDO2 key) can take the place of the code at login. It is bound to the server's domain, so a look-alike
  site cannot use it. The authenticator app stays required next to it as the fallback, so a lost phone
  does not lock the owner out. Adding or removing a passkey needs the password and the second factor (in a
  web session: a sign-in from the last 10 minutes) and sends an e-mail notice. So whoever holds one of the
  account's passkeys can add another one of their own; the owner is told by e-mail. Like TOTP it protects the login only (see below). The client (`cryptclient`)
  signs in with a passkey through the browser: it opens the web UI's approve page and receives the answer on
  a listener on 127.0.0.1 only. The one-time session token stays in the client, so an approve link sent by
  someone else cannot give them a session.
- **Delayed key replacement and deletion.** The SSH key is what opens the SFTP account, so a new key
  takes effect only after `CHANGE_DELAY_HOURS` (24 by default). The owner is e-mailed at once with a cancel
  link, the old key keeps working meanwhile, and the request is refused if that e-mail cannot be sent. Account
  deletion waits the same way. The first key of a new account takes effect at once.
- `api` and `cryptdaemon` talk over a Unix socket. Every command carries a timestamp, a nonce and an
  HMAC-SHA256 over the whole command (`DAEMON_AUTH_KEY`); stale and repeated commands are rejected. The
  daemon accepts only four SFTP-account actions and refuses any field that could carry a key.

## What is protected

- **Data at rest and from the server.** The server holds ciphertext, `gocryptfs.conf`, hashes and the
  recovery verifier. A copy of the disk, a backup, a database dump or a curious or compromised server does not
  reveal file contents or names (without escrow). A server that is compromised *while users sign in to the
  web UI* is the exception, see below.
- **The password never reaches an honest server**, including through the web UI (the browser derives the login
  key). The command-line client and the tray never send it anywhere.
- **Cross-user isolation.** Each user is a virtual SFTPGo user, public-key login only (password and keyboard-interactive login, FTP, WebDAV and the web interfaces are off), confined to its own directory, with a quota. There are no shell or system accounts and no port forwarding. SFTPGo's built-in defender bans repeated failed logins.
- **Lost or copied USB stick.** The key on it is encrypted under the password and a stick secret that
  the server releases only after the full login (password and second factor). Someone with the stick, or a
  copy of the Windows key file, cannot guess the password offline: every guess goes through the throttled
  login. A lost stick is locked in the web UI at once: its secret is no longer released. Only the app can
  unlock it, with the full sign-in. Removing it for good deletes the secret, so its key can never be opened
  again. Removal waits `change_delay_hours` with a cancel e-mail, like account deletion. So a stolen
  passkey, which alone opens a web session, can lock a stick but not remove it unnoticed. Sticks
  prepared before this are sealed on their next connect.
- **Stolen password.** Not enough on its own: it needs the second factor, and even with both a new SSH key
  waits while the owner is told and can cancel.

## What is NOT protected (read this before deploying)

- **Typing the password into the web UI trusts the server.** The server also serves the JavaScript that
  derives the login key. A compromised or malicious server can serve a version that sends the password back,
  derive the volume key from it and read all of that user's files. The client and the tray are not affected.
  So the web UI does not need the password: sign in there with a **passkey alone** (the device must verify you:
  PIN, fingerprint or face) or with **`cryptclient web-login`**, where the app signs in and hands the page a
  one-time ticket (two minutes, once). The dashboard never asks for the password; sensitive actions there are
  confirmed by a sign-in from the last 10 minutes. A web session cannot open the storage: the API refuses it the
  stick secrets, the storage address, key and password changes, the escrow and a new ticket. The password form is
  still there for accounts without a passkey, folded away and labelled as trusting the server. Creating the
  account in the web UI types the password there too: create it with `cryptclient setup` if you do not trust the
  server. A malicious server can still show a fake page that *asks* for the password; never type it into the
  web UI if you use a passkey or the app.
- **Offline copies (sync) are plaintext on the computer.** The client warns when disk encryption (BitLocker,
  LUKS, FileVault) is off; a stolen laptop without it exposes the synchronised files.

- **A malicious server can delete files, restore older versions and swap files** (a gocryptfs property). It
  also sees file sizes, the number of files and access timing. A signed manifest to detect this is future work.
  What the user sees, checked by the integration tests (`TestIntegrationTamper`, `TestIntegrationSyncTamper`):
  - *Not noticed:* two files in one folder swapped (each shows the other's content), an older version put back,
    a file deleted. With `connect --sync` these reach the local copy too: the synchronised folder is not a backup. The
    local file that is deleted or rolled back is kept for 30 days in the folder's `.secdisk-trash`.
  - *Read error, never wrong content:* a file cut short or with a changed byte (AES-GCM). The sync names the file,
    keeps the local copy and leaves the file out; the other files go on syncing.
  - *Files vanish:* a file moved to another folder, or a folder's `gocryptfs.diriv` replaced (all its names stop
    decrypting). When more than half of the files vanish at once, the sync stops (safety stop) and keeps the local copies.
  - *Old password works again:* an old `gocryptfs.conf` put back after a password change opens with the old
    password and refuses the new one. The master key never changes with the password. The client removes the
    previous config (`gocryptfs.conf.bak`) once a change is done and on every connect, but a server or a
    backup that kept a copy still opens with the old password: a password change does not lock out someone who
    knew the old password and holds a copy of the server's files. That needs a new master key.
  - *Recovery refused:* a replaced check file (`.secdisk-canary`) makes recovery with the right code fail.
- **Offline guessing.** The server holds `gocryptfs.conf` and the login hash, so a weak password can be guessed
  offline. The apps require 12 characters but do not check strength: use a long passphrase. A stick whose
  key is not sealed yet (an older stick before its first connect, or a server without `TOTP_ENCRYPTION_KEY`)
  can still be guessed offline, and so can a stick secret by someone who also holds a full copy of the server
  including `TOTP_ENCRYPTION_KEY`.
- **Recovery depends on the recovery code** (or escrow). If a user loses both the password and the code, and
  there is no escrow, the data is gone; there is no administrator override. The recovery code is as powerful
  as the password. **Back up the database and the SFTP data directory and test restoring them**
  ([docs/BACKUP.md](docs/BACKUP.md)).
- **A compromised client machine** is exposed while the storage is open.
- **TOTP and passkeys on the account protect the server login only**, not the data against someone holding a copy of the server's files.
  The volume key comes from the password alone, so a stolen password plus a copy of `gocryptfs.conf` and the
  ciphertext (from the server, a backup, or through a key change the owner did not cancel) opens the data.
- **E-mail is part of the protection.** The enrolment code and the cancel links go to the account's address;
  whoever controls that mailbox can use them. Without SMTP (development mode) they are only logged.
- **Quotas** are enforced by SFTPGo per user as files are written; the counter is SFTPGo's own, so a restore from backup should be followed by a quota rescan.
- **The USB serial-number binding is weak** (serials can be cloned); the real protection is the password-encrypted key.

## Known weaknesses and hardening backlog

Known and not yet fixed, listed so that reviewers and users do not have to rediscover them.

- **Throttling state is in memory** (login and recovery failures, rate limits, the web tickets already used).
  It resets when the API restarts, and the API must run as a single process.
- **The web ticket travels in a link** (`index.php#ticket=…`). The part after `#` is never sent to the server, so
  it stays out of access logs and the Referer header; the page posts it with its CSRF token and removes it from
  the address bar and history at once. It works once and for two minutes. A link made by someone else signs your browser in
  to *their* account, not yours (the dashboard shows whose account is open).
- **The key on the stick is a file** in its hidden `.secdisk` folder, on Linux and Windows alike, so it can be
  copied. A copy is useless without the password, the second factor and the stick secret the server releases
  after both (key format v3); the serial binding is weak (see above). Each OS family keeps its own serial
  binding, and a stick bound only on the other one is bound at its first use (trust on first use). Sticks
  prepared on Linux by older versions keep the key in raw sectors 1 MiB into the stick until prepared again.
- **Windows:** the client refuses to run as administrator (SSHFS-Win cannot write from an elevated token);
  the SSH key is written to a temporary file for the moment of connecting; cppcryptfs receives the derived volume
  passphrase on its command line for the moment of mounting; the installer is not code-signed yet.
- **macOS** compiles but is untested.
- **`cryptdaemon` trusts any process that can open its socket and knows the key.** The peer uid check
  (`CRYPTDAEMON_ALLOWED_UIDS`) is optional and off by default. The daemon runs as the system account `cryptstorage` (no login), which is also the SFTPGo container's user and owns the storage; not as root, without capabilities and with a read-only system (`ProtectSystem=strict`).
- **Deployment secrets live in the Ansible inventory** unless you move them to Ansible Vault. The playbook refuses
  placeholders and `generate-secrets.sh` creates real values.
- **The production Ansible roles** (nginx/TLS, fail2ban, UFW, the SFTPGo container) are not exercised by CI. Docker publishes the SFTP port itself, around UFW.
- **The SFTPGo admin password** is a random value in `/etc/cryptdaemon/sftpgo-admin` and in the compose file; its REST API listens on the loopback only.
- **The test-server deployment** (`scripts/deploy_testserver.sh`) is not a production layout: the API runs as
  root, plain HTTP, no e-mail verification.

## Deployment guidance

- **Generate unique secrets.** Never deploy with the `CHANGE_ME` placeholders (the playbook
  and the API both refuse to start with them); `ansible/generate-secrets.sh` prints fresh ones.
  `JWT_SECRET_KEY` should be at least 32 random bytes; `REFRESH_TOKEN_HMAC_KEY` is
  64 hex characters (`openssl rand -hex 32`); `DAEMON_AUTH_KEY` is generated by the
  Ansible `cryptdaemon` role. Keep secrets out of version control.
- **TLS only.** Use the `ssl` role (nginx) and keep `REQUIRE_EMAIL_VERIFICATION` on.
- **Keep the interactive API docs off.** `/docs` and `/openapi.json` are disabled unless
  `ENABLE_DOCS=true`; CORS is off unless `CORS_ORIGINS` lists origins.
- **Keep the API private.** In the shipped compose file, port 8000 is bound to
  `127.0.0.1`; do not publish it on a public interface.
- **Keep the daemon socket private.** Only members of the `cryptapi` group (the API
  container) may use it, and the HMAC key is still required.
- **Keep the SFTP port (default 2222) reachable** and nothing else of the host's SSH exposed more than needed.
- **Patch** the kernel, Docker and the base images regularly, and update the pinned SFTPGo version (`scripts/install_sftpgo.sh`, the compose file) when it publishes security fixes.
- **Back up** the database and the SFTP data directory (see above).

## Scope

In scope: the code and default deployment in this repository.

Out of scope: volumetric denial of service, social engineering, findings that require
root on the server (see "What is NOT protected"), and vulnerabilities in third-party
software (please report those upstream; we are happy to be told about them too).
