# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org/); before
1.0 any release may change the storage format or the API, and the release notes say how to move over.

## [0.1.3] – 2026-11-12

Version 0.1.2 was not released; its changes are part of this one.

### Security
- **The app refuses a volume whose settings were changed on the server.** `gocryptfs.conf` is kept on the
  server, and the list of features in it is not covered by the key check. A server that edited it could
  make the app store the names of new files unencrypted. File contents were not affected, and files
  written before the change kept their encrypted names. The app now accepts only the exact settings
  it creates itself and mounts from a checked local copy, never from the server's file directly.
  **Update the app on every computer.** Operators can then set `min_client_version: 0.1.3`.
- **The second factor can no longer be guessed patiently.** Five wrong codes locked it for 15 minutes,
  again and again, without the owner hearing of it. The lock now grows (15 minutes, 1 hour, then 24 hours
  each time) and the owner gets an e-mail when it starts.
- **The web UI's passkey sign-in no longer tells which names have an account** (the answer for an unknown
  name is now stable between requests, and wrong answers are throttled alike).
- **fail2ban no longer bans an address for normal sign-ins.** Every sign-in with an authenticator app
  passes a "code required" answer that the filter counted as a failed login, so a shared office address
  was banned after a few users signed in. The API marks that answer and the filter skips it.

### Added
- **The app says when a newer version exists.** The server announces the newest app version
  (`latest_client_version`, by default its own release version), and an older app shows a notice
  on the command line and an "Update to version X..." entry in the tray menu. Nothing is downloaded
  or installed by itself. The entry opens the project's release page: that address is fixed in the
  app, so a server can announce a number but cannot send users to a download of its own.
- **`install.sh`: installing on the server itself.** It checks the server (system, memory, disk,
  ports, DNS), asks for the domain, the mail server (required) and the registration mode, generates the secrets, saves
  the settings in `/etc/cryptstorage/inventory.yml` and runs the same Ansible playbook as before
  against the local machine, with Ansible in a directory of its own. Running it again applies
  changed settings. `--check` only looks. Installing from another machine works as before.
- **`cryptstorage-update`** on a server installed that way: downloads the new version's server
  package, checks it against the signed `SHA256SUMS` (with `cosign`, which `install.sh` installs in a fixed, checksum-verified
  version; `--no-signature-check` to go without), checks the server, **takes a backup**, installs and waits for the server to report the
  new version. The backup holds what an upgrade changes (database, SFTPGo state, settings, keys);
  **`--full`** makes it complete, the users' files included. It runs only when started by hand.
- **Releases carry a server package** (`cryptstorage-server-X.Y.Z.tar.gz`), listed in the signed
  `SHA256SUMS` like the app files.
- `cryptstorage-backup --without-files`, and `/etc/cryptstorage` in every backup when it exists.
- Settings `tls_mode: selfsigned` (tests and closed networks) and `ssh_port` (the firewall and
  fail2ban follow the port sshd really uses; default 22 as before).
- **Registration modes.** `registration: open` (default, as before), `invite` or `closed`, and optionally
  `registration_email_domains`. The apps and the web UI ask for the invitation code.
- **`cryptstorage-admin`** on the server: list and show accounts, lock and unlock (also closes the
  account's storage connections), set a quota, remove a lost second factor, confirm an e-mail address,
  delete an account, and make, list and revoke invitations. See `ansible/README.md`, "Administration".
- Accounts whose e-mail address is not confirmed within 24 hours are removed.
- **Database migrations** run when the API starts (`api/migrate.py`, table `schema_version`), and a
  database from a newer version is refused instead of used. Upgrading and going back:
  [docs/UPGRADE.md](docs/UPGRADE.md).
- `min_client_version`: apps older than the given version ask for an update (from 0.1.3 on).

### Changed
- Build and deployment are pinned more tightly: every Python package with its hash
  (`api/requirements.lock`), base images by digest, workflow actions by commit, the Go toolchain named in
  `go.mod`; the dependency checks cover indirect dependencies and fail the build.
- CI installs a server from scratch with `install.sh` and updates it twice with
  `cryptstorage-update`, on every change to the server side.

### Moving over
- Server: deploy as in [docs/UPGRADE.md](docs/UPGRADE.md). New tables are created at start-up; nothing to
  run by hand. The playbook must be run in full (nginx and fail2ban change, not only the containers).
- An open server stays open: set `registration` in the inventory if that is not what you want.
- A server installed from another machine keeps being deployed from there. To manage it with
  `install.sh` and `cryptstorage-update` instead, see `ansible/README.md`, "Moving the settings
  onto the server". **Do not run `install.sh` with new settings on an existing server**; it refuses.

## [0.1.1] – 2026-11-03

### Security
- **Per-server password salt (key derivation version 2).** The salt of the password's Argon2id run now
  includes a random 32-byte value that each server creates once (`kdf_salt`, public in `/server-info`,
  stored in the database). Before, it came from the username alone, so guesses for a known username could
  be computed before any server's data was taken, and the same username had the same salt on every server.
  Login still reveals nothing about which accounts exist. Details: [docs/design-e2ee.md](docs/design-e2ee.md),
  section 5a.

### Moving over (automatic)
- Existing accounts and volumes move over the first time the user connects with the 0.1.1 app
  (`cryptclient connect`, the tray, `init-storage` or `setup`): the app re-wraps `gocryptfs.conf` under the new
  volume passphrase and then replaces the login key on the server. The files are not re-encrypted, and
  the password stays the same.
- **After the move, older apps (0.1.0) can no longer sign in to that account.** Update the app on every
  computer. Until an account has moved, 0.1.0 apps keep working.
- The web UI derives the new key in the browser and sends the old one next to it, so it signs in to
  accounts on either version; new accounts created there use version 2.
- Server: two new tables (`server_settings`, `user_kdf`) are created at start-up; nothing to migrate by hand
  (reference SQL in `api/migrations/013_kdf_v2.sql`). Keep the database backup: the salt is in it.

## [0.1.0] – 2026-10-31 (first public pre-release)

Personal encrypted storage: one user, one volume. Shared folders for groups come in 0.2. Not
independently audited. Read [SECURITY.md](SECURITY.md) before storing anything you cannot lose.

### Name
- The project is now **Venomia CryptStorage** (short: CryptStorage), formerly secdisk. The Windows
  tray is `CryptStorage.exe` and the installer `CryptStorageSetup.exe` (an update replaces a secdisk
  installation in place, with its starting at sign-in); the Linux user service is
  `cryptstorage-tray@.service`. The client moves its folders from `secdisk` to `cryptstorage` the first
  time it runs (`~/.config`, `~/.cache`, `~/.local/share`, `%AppData%`, `%LOCALAPPDATA%`); a synchronised
  `~/secdisk` folder keeps its name. Test and debug variables are now `CRYPTSTORAGE_*` and
  `CRYPTCLIENT_*` instead of `SECDISK_*`. Key derivation labels, the stick's `.secdisk` folder and the
  `.secdisk-*` files in a volume keep their names, so existing sticks and volumes work unchanged.
- Server: the system account is `cryptstorage`, the storage `/srv/cryptstorage` and the SFTPGo admin
  `cryptstorage`. A server installed with the earlier names is set up again from scratch (the playbook
  does not move the old account or data). The LAN test server (`scripts/deploy_testserver.sh`) moves its
  secrets over to `/etc/cryptstorage` by itself and starts with empty accounts, keeping the old data aside.

### Encryption and storage
- End-to-end encryption on the user's machine in the gocryptfs format (gocryptfs on Linux, cppcryptfs on
  Windows); the server stores only ciphertext in an [SFTPGo](https://github.com/drakkan/sftpgo) service.
- One password: the login key and the volume key are derived from it in the client (Argon2id + HKDF);
  the server never sees the password or the master key.
- Recovery code shown once at setup; `cryptclient recover` sets a new password without losing data.
- Optional operator escrow (`recovery_policy`), off by default. The client never seals a user's key
  without asking, keeps the accepted setting on the stick and warns loudly if the server's setting or
  escrow key changes; the web UI shows each user's escrow state, and the server keeps policy changes in
  a hash-chained log checked at start.
- Synchronised local folder (`connect --sync`): rclone bisync under a server-side lock per volume, with
  conflict copies and safety stops. The client warns when the folder's disk is not encrypted. Local files
  deleted or replaced because of the storage go to a 30-day trash in the folder first (it is a mirror,
  not a backup); a file in the storage that cannot be read is named and left out instead of stopping the
  sync, and an interrupted run recovers by itself with a full comparison.

### Sign-in and account protection
- USB key stick bound to its serial number holds the SSH key in its hidden `.secdisk` folder; the same
  stick works on Linux and Windows, and preparing it needs no `sudo` on Linux. Sticks prepared on Linux by
  older versions (raw sectors) keep working there.
  The key is sealed with a stick secret the server releases only after the full login, so a lost or
  copied stick cannot be attacked offline. A lost stick is locked in the web UI at once and unlocked only
  from the app; removing it for good waits like account deletion.
- A stick belongs to one server: it notes the server (`cryptstorage.server`: address and the server's
  `server_id`, which lasts as long as its stick secrets), and the client stops before the password when
  it is set to another server. The key is sealed only after an SFTP login with it worked, so a client set to
  the wrong server cannot tie the stick to it. `setup` asks before preparing a stick of another server; the
  tray menu and `cryptclient diagnose` show the server.
- Two-factor sign-in is mandatory: authenticator app (TOTP) with backup codes, plus passkeys (Face ID,
  fingerprint, phone via QR code, FIDO2 key) in the web UI and in the client through the browser. The web
  UI asks for the passkey first and offers the code as a fallback. Not yet tried: passkeys on an iPhone
  and through a phone's QR code (Bluetooth).
- The web UI does not need the password: sign in with a passkey alone, or with
  `cryptclient web-login` (also "Open account web page" in the Windows tray menu and in the Linux app
  menu), which hands the page a one-time ticket (after `#` in the link, so it never reaches server logs). A web session manages the account but
  cannot open the storage, and it confirms sensitive actions with a recent sign-in instead of the password.
  The password form stays, folded away and labelled as trusting the server.
- Replacing the SSH key and deleting the account wait 24 hours (configurable) and e-mail the owner a
  cancel link.
- The SFTP host key is vouched for by the API over the pinned TLS connection; no "trust this key?" prompt.
- Replacing the stored recovery verifier needs a second factor from the last five minutes and e-mails the
  owner, since it makes the old recovery code useless.

### Client
- `cryptclient setup`: guided first-time setup (account, stick, storage, recovery code).
- Linux: `.deb` package (pulls in gocryptfs, sshfs and fuse3), password dialogs, connects when the stick is
  plugged in. `cryptclient tray` puts a padlock in the panel (StatusNotifierItem over D-Bus, pure Go) with
  the same menu as on Windows: connect, disconnect, open the folders, the account web page, start at sign-in
  (XDG autostart, on after the first start), setup in a terminal. GNOME shows it with the AppIndicator
  extension (Ubuntu has it); without a tray area the stick still opens with dialogs (udev).
- Windows: installer; SSHFS-Win and cppcryptfs (the installer keeps cppcryptfs and rclone in
  `Program Files\CryptStorage`, out of the user profile). `CryptStorage.exe` puts a padlock next to the clock, asks for
  the password in a window when the stick is plugged in, and connects, disconnects and opens the folder
  from its menu; it starts at sign-in (can be turned off in the menu). The exe files carry an icon and
  version information.
- `cryptclient diagnose` prints what the machine has and lacks, for help requests.
- macOS compiles but is untested and not supported in this release.

### Server
- Ansible deployment: nginx + TLS, Docker (API, web UI, MariaDB, SFTPGo), firewall, fail2ban.
- Web UI for account information only; it never shows files.
- Backup and restore guide ([docs/BACKUP.md](docs/BACKUP.md)).

### Releases
- Release builds from a tag with `SHA256SUMS` and keyless cosign signatures
  ([docs/verify-release.md](docs/verify-release.md)). Windows binaries are not Authenticode-signed yet
: Windows SmartScreen asks for "More info → Run anyway".
- Every build says which code it is: the release version, or `dev+<commit> (<date>)` otherwise. The
  client shows it in `cryptclient version`, `diagnose` and the tray menu; the server in `/server-info`,
  `/health` and the web UI footer (`scripts/version.sh`, written at deploy).
