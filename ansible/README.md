# Ansible – Automated installation

Installs the whole CryptStorage stack on one server: nginx + Let's Encrypt, Docker (api, webui,
db, SFTPGo), cryptdaemon, firewall, fail2ban, automatic security updates.

Tested from a clean install on Ubuntu 26.04 (1 vCPU, 1 GB RAM VPS). Also meant for
Ubuntu 24.04 and Debian 12/13; the playbook stops at once on anything else.

---

## What you need

**The server**
- A fresh Ubuntu 24.04+ or Debian 12+ with `python3`, reachable over SSH as root (or a user with
  sudo) with an SSH **key**. The playbook turns password logins off.
- At least 1 GB RAM. Below 2 GB the playbook adds a 2 GB swap file (`swap_size_mb`).
- A domain name whose A (and AAAA) record points to the server, and ports 80 and 443 reachable
  from the internet: Let's Encrypt checks the domain over HTTP. A server on a home LAN without
  port forwarding cannot get a certificate this way.
- Ports the firewall opens: 22 (SSH), 80, 443 and `sftp_port` (default 2222).

**The control machine** (where you run Ansible): Linux, macOS, or Windows with WSL. Ansible does
not run on Windows itself.

---

## Usage

```bash
# 0. SSH key for the server (skip if you have one), then put the .pub line into the
#    server's ~/.ssh/authorized_keys or the provider's "SSH keys" field before installing it
ssh-keygen -t ed25519

# 1. Ansible and the collections
pipx install --include-deps ansible     # or: sudo apt install ansible
cd ansible
ansible-galaxy collection install -r requirements.yml

# 2. Copy the project files into the roles
./setup-files.sh

# 3. Your inventory (keep it out of git: it will hold the secrets)
cp inventory/hosts.yml inventory/my-hosts.yml
chmod 600 inventory/my-hosts.yml
./generate-secrets.sh                    # paste these over the CHANGE_ME values
# then set ansible_host, ansible_user, domain, letsencrypt_email and the SMTP settings

# 4. Run the playbook (it can be run again; later runs only fix what has changed)
ansible-playbook -i inventory/my-hosts.yml site.yml

# Or only a specific role:
ansible-playbook -i inventory/my-hosts.yml site.yml --tags daemon
```

The playbook refuses to run with `CHANGE_ME` placeholders or short secrets. Rather than keeping the
secrets as plain text, encrypt them with Ansible Vault:
```bash
ansible-vault encrypt_string 'secret-value' --name 'db_password'
```

### From Windows (WSL)

```powershell
wsl --install -d Ubuntu-24.04
```
Then, inside Ubuntu: `sudo apt install git pipx` and follow the steps above. Two things go wrong
otherwise:
- **Clone the repository inside WSL** (`git clone` in your Linux home). A clone made with Git for
  Windows may have CRLF line endings in older checkouts, which break the scripts on the server.
- **Do not run Ansible from `/mnt/c` or `/mnt/h`.** Those files look world-writable to Linux, and
  Ansible then ignores `ansible.cfg`. Copy an existing key with
  `cp /mnt/c/Users/<you>/.ssh/id_ed25519* ~/.ssh/ && chmod 600 ~/.ssh/id_ed25519`.

---

## Structure

```
ansible/
├── site.yml                    # Main playbook
├── requirements.yml            # Galaxy collections
├── setup-files.sh              # Copies the sources into the roles' files/ directories
├── generate-secrets.sh         # Prints fresh values for the secrets
├── inventory/
│   └── hosts.yml               # Example inventory: copy it, fill it in
├── tests/                      # CI test of the SFTPGo container
└── roles/
    ├── base/                   # Packages, swap, time zone, locale, sysctl, security updates, key-only SSH
    ├── firewall/               # UFW: 22, 80, 443 and the SFTP port
    ├── fail2ban/               # SSH + API brute-force protection
    ├── docker/                 # Docker Engine + Compose from Docker's repository
    ├── cryptdaemon/            # Host daemon + systemd + keys, SFTPGo state and host keys
    ├── cryptstack/             # Docker containers (api, webui, db, sftpgo)
    ├── ssl/                    # Nginx reverse proxy + Let's Encrypt
    ├── logrotate/              # Log rotation (cryptdaemon + nginx)
    └── verify/                 # Health checks + installation summary
```

---

## Inventory variables

| Variable | Description |
|----------|-------------|
| `ansible_host`, `ansible_user` | Server address and SSH user (root, or a sudo user) |
| `domain` | Server domain (e.g. `crypto.example.com`); its DNS must point to the server |
| `letsencrypt_email` | E-mail for the Let's Encrypt certificate |
| `db_root_password`, `db_password` | MariaDB passwords (16+ characters) |
| `jwt_secret_key` | JWT signing key (32+ characters) |
| `refresh_token_hmac_key`, `totp_encryption_key` | 64 hex characters each (`openssl rand -hex 32`) |
| `smtp_host`, `smtp_port`, `smtp_user`, `smtp_password`, `smtp_from`, `smtp_security` | Mail for e-mail verification and change notices. Empty `smtp_host` = no mail. `smtp_security`: `starttls` (587) or `ssl` (465; the default on that port). **Without mail users cannot turn on the mandatory authenticator app** |
| `require_email_verification` | `"true"` (needs SMTP) or `"false"` |
| `sftp_port` | Public port of the SFTP storage service (default 2222) |
| `storage_dir` | Where the users' ciphertext is kept (default `/srv/cryptstorage`) |
| `recovery_policy`, `escrow_public_key` | `user`, `escrow` or `both` (docs/design-e2ee.md) |
| `registration` | Who may create an account: `open` (anyone who reaches the server; the default), `invite` (only with a code from `cryptstorage-admin invite create`) or `closed`. **Set `invite` or `closed` on a server that is not meant for the public** |
| `registration_email_domains` | Optional. Only addresses of these domains may register, e.g. `example.org,example.com` |
| `min_client_version` | Optional, e.g. `0.1.2`. Clients older than this tell their user to update instead of opening the storage (clients before 0.1.2 do not know the setting and are not stopped by it) |
| `required_factors`, `change_delay_hours` | Account protection (docs/design-factors.md) |
| `server_timezone`, `server_locale` | Optional, e.g. `Europe/Helsinki`, `fi_FI.UTF-8` (default UTC, image locale) |
| `swap_size_mb` | Swap file made when RAM < 2 GB (default 2048, `0` = never) |
| `demo_quota_mb`, `demo_max_users`, `demo_account_lifetime_hours` | **Demo server only.** Quota of new accounts, cap on accounts, and deletion of accounts (with their data) after N hours. Off by default |
| `client_downloads_src` | Optional. A folder **on the control node** with the client builds (Windows installer, `.deb`, binaries, as `.github/workflows/release.yml` makes them). The playbook serves them at `https://<domain>/download/` with a page listing their SHA-256 sums, and the web UI links to it. Re-run with `--tags downloads` after a new build; files no longer in the folder are removed. Empty = no download page |
| `ssh_keys_only` | Turn off SSH password logins (default true; skipped if `ansible_password` is set) |

---

## Registration by invitation

By default anyone who reaches the server can create an account (`registration: open`). That suits a
public or demo server. For a company, a club or a family, switch to invitations:

1. In your inventory set
   ```yaml
   registration: invite
   # registration_email_domains: example.org     # optional: only these addresses
   ```
   and run the playbook (`ansible-playbook -i inventory/my-hosts.yml site.yml`). Existing accounts
   are not affected.
2. For each new person make a code on the server:
   ```bash
   sudo cryptstorage-admin invite create --email bob@example.org --note "Bob, sales"
   ```
   It prints the code once. `--email` ties the code to that address (recommended: a forwarded code is
   then useless to anyone else); `--days` sets how long it is valid (default 7).
3. Send the code to the person over a channel you trust. They run `cryptclient setup` (or use the
   web UI's Register tab), which asks for it. A code works for one registration.
4. `sudo cryptstorage-admin invite list` shows which codes are open, used or expired, and
   `invite revoke <id>` removes an unused one.

`registration: closed` refuses every registration, with or without a code: use it when everyone is in,
or to pause sign-ups. Switching between the modes only needs the inventory line and a playbook run.

---

## Administration

The playbook installs `cryptstorage-admin` on the server (it runs `api/admin.py` inside the API container):

```bash
sudo cryptstorage-admin users                     # all accounts; --state locked|unverified|active
sudo cryptstorage-admin show alice                # one account: state, storage used, second factor
sudo cryptstorage-admin lock alice                # no sign-in, sessions ended, storage connections closed; data kept
sudo cryptstorage-admin unlock alice
sudo cryptstorage-admin quota alice 20G           # or 500M
sudo cryptstorage-admin reset-2fa alice           # removes the authenticator app and passkeys; the user is told by e-mail
sudo cryptstorage-admin verify alice              # mark the e-mail address confirmed (the e-mail did not arrive)
sudo cryptstorage-admin delete alice --yes        # the account and all its data, at once
sudo cryptstorage-admin invite create --email bob@example.org --days 7
sudo cryptstorage-admin invite list
sudo cryptstorage-admin invite revoke <id>
```

Every change is written to the audit log (`security_events`, `admin_*`). The command cannot open anyone's
files or reset a forgotten password: the keys exist only on the users' side. Before `reset-2fa`, make sure
who is asking: after it the password alone signs in until the user sets up a new second factor.

An account whose e-mail address is not confirmed within 24 hours is removed (the link has expired by
then), so an unfinished or mistyped registration does not hold its name and address for good.

---

## Automatically generated values

| Value | Location | Description |
|-------|----------|-------------|
| `DAEMON_AUTH_KEY` | `/etc/cryptdaemon/auth.key` | HMAC key for socket authentication |
| SSL certificate | `/etc/letsencrypt/` | Let's Encrypt, renews automatically |

---

## Roles

### base
Base packages, swap on small servers, time zone and locale, sysctl hardening, automatic security
updates (unattended-upgrades) and key-only SSH (`/etc/ssh/sshd_config.d/00-cryptstorage.conf`).

### firewall
UFW: allows ports 22 (SSH), 80 (HTTP), 443 (HTTPS) and the SFTP port (`sftp_port`, default 2222).
UFW is reset only on the first run (marker `/etc/ufw/.cryptstorage`); rules you add later by hand
are kept.

### fail2ban
Protects SSH and the API against brute-force attacks. The SFTPGo service has its own defender (bans repeated failed logins).

### cryptdaemon
Copies the daemon files, installs the Python dependencies,
generates the auth key (`/etc/cryptdaemon/auth.key`),
registers the systemd service.

### cryptdaemon (SFTPGo)
The storage service itself is the `sftpgo` container of the compose file (pinned image, public-key SFTP on `sftp_port`, REST API on 127.0.0.1:8081, no web interfaces). Its admin password is generated once into `/etc/cryptdaemon/sftpgo-admin`. The user data lives in `storage_dir` (default `/srv/cryptstorage`, owned by the system account `cryptstorage`, a free system uid picked at install unless `storage_uid` is set, which also runs the SFTPGo container and cryptdaemon) and SFTPGo's state in `<install_dir>/sftpgo`; back both up (`docs/BACKUP.md`). Also set `recovery_policy` (`user`, `escrow`, `both`) and, for escrow, `escrow_public_key`.

### cryptstack
Starts Docker Compose (api + webui + db + sftpgo) and installs the backup script as
`/usr/local/sbin/cryptstorage-backup` (docs/BACKUP.md) and the administration command as
`/usr/local/sbin/cryptstorage-admin` (see Administration above).

### ssl
Nginx reverse proxy; obtains the Let's Encrypt certificate
with Certbot automation.

### logrotate
Daily log rotation: `cryptdaemon.log` (14 days) and
nginx logs (30 days), compressed.

### verify
Checks that all services respond and prints
an installation summary.
