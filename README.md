# CryptStorage

**Venomia CryptStorage** (short: CryptStorage, formerly secdisk) is self-hosted **end-to-end encrypted**
personal cloud storage. Files are encrypted on the user's own machine
([gocryptfs](https://nuetzlich.net/gocryptfs/) format; cppcryptfs on Windows); the server stores
only ciphertext. The user connects with one password and a USB key stick, and the encrypted volume
appears as a normal folder or drive.

> **Status: pre-release, not independently audited. Do not use it for the only copy of data you cannot
> afford to lose.** Read [SECURITY.md](SECURITY.md) first: it says what
> the design protects and what it does not (a malicious server cannot read files, but it can delete or roll
> them back, and it sees sizes and timing). The design is in [docs/design-e2ee.md](docs/design-e2ee.md).

## How it fits together

```
  user machine                              server
  ┌──────────────────┐   HTTPS   ┌─────────┐        ┌──────────┐  Unix socket  ┌─────────────┐
  │ cryptclient (Go) │──────────▶│ nginx   │───────▶│ api      │──────────────▶│ cryptdaemon │ cryptstorage
  │ encrypts/decrypts│  login    │ ├ webui │        │ (FastAPI)│  (HMAC auth)  │ SFTPGo users │
  │ + USB key stick  │           │ └ /api  │        └────┬─────┘               └──────┬──────┘
  │       │ SFTP/SSHFS│  SFTP port└─────────┘          MariaDB                         │
  └───────┴──────────┘◀──────────────────────────▶ SFTPGo (public-key SFTP, ciphertext only)
```

| Directory | What it is |
|---|---|
| `api/` | FastAPI service: accounts, login, tokens, recovery verifier, escrow blob |
| `cryptdaemon/` | Daemon on the host: creates and removes the users of the [SFTPGo](https://github.com/drakkan/sftpgo) storage service (REST API) |
| `webui/` | PHP web interface: account information only; the login key is derived in the browser |
| `cryptclient/` | Go client: setup, USB key stick, encryption, SSHFS mount (Linux, Windows 10+; macOS untested) |
| `ansible/` | Deployment: nginx + TLS, Docker (api, webui, db, SFTPGo), firewall, fail2ban, systemd |
| `scripts/`, `docs/` | Backup script, [backup/restore guide](docs/BACKUP.md), and the [end-to-end design](docs/design-e2ee.md) |
| `tests/` | pytest suite (see below) |

## Deploying

One fresh Ubuntu 24.04+ or Debian 12+ server (1 GB RAM is enough), a domain pointing to it, and
Ansible on Linux, macOS or Windows WSL. Full steps: [ansible/README.md](ansible/README.md).

```
cd ansible
ansible-galaxy collection install -r requirements.yml
./setup-files.sh                                     # copies the sources into the roles
cp inventory/hosts.yml inventory/my-hosts.yml
./generate-secrets.sh                                # real values for the CHANGE_ME placeholders
$EDITOR inventory/my-hosts.yml                       # server, domain, e-mail, secrets, SMTP
ansible-playbook -i inventory/my-hosts.yml site.yml
```

The playbook refuses to run with `CHANGE_ME` placeholders, and the API refuses to start without
real secrets. Set `recovery_policy` (`user`, `escrow` or `both`) and, for escrow, `escrow_public_key`
(`scripts/escrow.py keygen`). Set up backups before inviting users ([docs/BACKUP.md](docs/BACKUP.md)).

## Using it

Windows 10+ and Linux. On Windows the installer sets up the required components; then run
`cryptclient setup`: it walks through account creation, e-mail confirmation, the USB stick, the storage
and the **recovery code (shown once)** in one conversation. Afterwards `cryptclient connect` asks for
your password, unlocks the key from the stick, and opens the encrypted storage as a folder or drive.
The web UI shows account information only (login details, disk usage, two-factor). A forgotten password
can only be recovered with the recovery code (or, if the operator enabled escrow, by the operator).

More in [cryptclient/README.md](cryptclient/README.md) and [webui/README.md](webui/README.md).

## Requirements and design principles

- **Two factors for every access.** The password alone is never enough: access needs a second factor
  such as the USB key stick, a device-bound key or a phone one-time code (see
  [docs/design-factors.md](docs/design-factors.md)). Today the stick opens the storage, and the account
  login also needs an authenticator app code or a passkey. The SSH key is not a
  readable file. Ordinary SFTP clients are not a supported way in. This deters casual copying; the real
  protection is the factors together (see [SECURITY.md](SECURITY.md)).
- **No file browsing in the web UI.** It shows account information only: login details, disk
  usage, password change and similar.
- **Supported client platforms:** Windows 10 or newer and current Linux distributions. macOS builds
  but is untested and not supported in v0.1.
  Windows 7 and 8 are not supported.

## Development

```
pip install -r requirements-dev.txt
python -m pytest -q             # unit tests, API <-> daemon smoke test, web UI against a stub API
python -m pyflakes api cryptdaemon tests
cd cryptclient && go vet ./... && go test ./...
```

The web UI tests need `php` on the PATH and are skipped otherwise. The client flows run against a real API, SFTPGo, sshfs and gocryptfs in CI, and on a real Windows machine
(see [docs/windows-testing.md](docs/windows-testing.md)). The production Ansible roles (nginx/TLS, fail2ban,
UFW) are not exercised by CI: try them on a test server before relying on them.

## Third-party software

The storage service is [SFTPGo](https://github.com/drakkan/sftpgo) by Nicola Murino (AGPL-3.0, with additional
attribution terms in its `NOTICE`). It runs unmodified as a separate service; its source is at the link above.

## License

[GNU Affero General Public License v3.0 only](LICENSE) (`AGPL-3.0-only`), Copyright (c) 2026 Matti
Mieskonen ([@valveo](https://github.com/valveo)).

You may use, modify and share CryptStorage for any purpose, including inside a company. If you change it
and let others use the changed version, also over a network (for example by hosting it as a
service), you must offer them the complete source code of your version under the same license.

If you want to use CryptStorage in a way the AGPL does not allow, for example a paid service or product
without publishing your changes, contact the author through GitHub
([@valveo](https://github.com/valveo)) about a separate commercial license.

Versions published before 2026-10-25 were under the PolyForm Shield License 1.0.0.
