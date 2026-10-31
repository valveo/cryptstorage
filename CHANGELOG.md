# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org/); before
1.0 any release may change the storage format or the API, and the release notes say how to move over.

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
