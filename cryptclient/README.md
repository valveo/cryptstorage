# cryptclient

A Go-based client for the CryptStorage service. Detects the cryptkey
USB stick automatically, decrypts the SSH key and mounts the
encrypted storage locally with SSHFS.

---

## File structure

```
cryptclient/
├── main.go                     # CLI entry point
├── keygen.go                   # ECDSA P-256 SSH key pair generation
├── build.sh                    # Cross-compile for all platforms
├── go.mod
├── usb/
│   ├── detect.go               # USB stick detection via magic bytes
│   ├── stickfiles.go           # The key and serial bindings in the stick's hidden .secdisk folder
│   ├── prepare.go              # Mounting the stick, clearing an old raw key before a new one
│   ├── rawkey.go               # Reading/writing a key in raw sectors (sticks from older Linux versions)
│   ├── layout.go, erase*.go    # Checking the raw layout; erasing and formatting a stick (Linux)
│   ├── serial.go               # Serial number detection + binding
│   ├── watch.go                # Watching for stick removal (polling)
│   └── check.go                # Device check for the udev trigger
├── crypto/
│   ├── unlock.go               # Argon2id + AES-256-GCM (formats v1/v2; v1 is the old PBKDF2)
│   └── sealed.go               # Format v3: sealed with the server's stick secret
├── stickkey/, stick_seal.go    # Opening the stick's key with the stick secret; sealing older keys
├── sshconn/
│   ├── agent.go                # In-memory ssh-agent for sshfs
│   ├── connect.go              # SSHFS mount/umount
│   ├── hostkey.go              # Host key pinning (keys vouched for by the API)
│   ├── mount_windows_drive.go  # SSHFS-Win on Windows
│   └── tempkey.go              # Short-lived key file for SSHFS-Win (Windows)
├── tray/
│   └── tray.go                 # Desktop dialogs for Linux (zenity)
├── sni/                        # Linux tray icon: StatusNotifierItem + dbusmenu over D-Bus (pure Go)
├── wingui/                     # Windows tray icon, password windows, autostart (Win32, no cgo)
├── nowindow/                   # starts helper programs without console windows
├── apiclient/
│   ├── client.go               # REST API client
│   ├── e2ee.go, sticks.go, sync.go, passkey.go  # calls for storage, stick secrets, sync lock, passkeys
│   └── pin.go                  # TLS public-key pinning
├── browserlogin/               # passkey sign-in through the browser, answer on 127.0.0.1
├── e2ee/                       # key derivation, gocryptfs.conf, recovery code, escrow, gocryptfs/cppcryptfs drivers
├── escrowcheck/, escrow_cmd.go # the escrow setting accepted on the stick, warning when it changes
├── syncer/, sync_cmd.go        # synchronised folder: rclone bisync, sync lock, trash, unreadable files
├── diskenc/                    # is the synchronised folder's disk encrypted? (LUKS, BitLocker, FileVault)
├── deps/, deps_cmd.go          # Windows components and rclone: pinned versions and SHA-256
├── weblogin_cmd.go             # `web-login`: the account web page without typing the password
├── volume/                     # connect / init / unlock / change password / recover flows (+ integration test)
├── setup/                      # the guided setup, tested with a scripted user against the real server
├── e2ee_cmds.go                # interactive commands for the above
├── setup_cmd.go, diagnose.go   # `setup` and `diagnose`
├── udev/
│   ├── 70-cryptclient.rules    # Linux udev rule for auto-detection
│   ├── cryptstorage-tray@.service   # User service the rule starts
│   └── install-udev.sh         # Installation script
└── packaging/
    ├── build-all.sh            # Cross-compile all binaries
    ├── linux/
    │   ├── build-deb.sh        # Ubuntu/Debian .deb package
    │   └── build-rpm.sh        # Fedora/RHEL .rpm package
    ├── macos/
    │   └── build-pkg.sh        # macOS .pkg universal binary
    └── windows/
        └── cryptstorage.iss          # Windows installer (Inno Setup; downloads the drivers on install)
```

---

## Usage

```bash
# Initialize the stick (once)
cryptclient init-usb

# docs/design-e2ee.md:
cryptclient setup             # guided first-time setup: account, stick, storage, recovery code (repeatable)
cryptclient diagnose          # what this computer has and lacks; paste it into a help request
# or step by step:
cryptclient register          # create the account (one password: login key and volume key are derived from it)
cryptclient init-usb          # prepare the stick (use the same password)
cryptclient init-storage      # create the encrypted storage, shows the recovery code once
cryptclient change-password   # new password for account, stick and storage together
cryptclient recover           # forgotten password: recovery code + new password; data stays intact
cryptclient web-login         # open the account web page signed in, without typing the password there
#                               (also in the Windows tray menu and the Linux app menu; without a terminal it uses dialogs)
cryptclient server [address]  # show or change the server (also "Change server..." in the tray menu). The account and
#                               the stick belong to one server: on a new one, run `setup` again (it re-prepares the stick).
#                               A bare address such as storage.example.com also finds an API under /api.
# `cryptclient connect` detects the server's mode by itself. Needs gocryptfs and sshfs (Linux, macOS).

# Connect
cryptclient connect
# → Finds the USB stick automatically
# → Checks the serial number (copy prevention)
# → Asks for the password
# → Second factor: press Enter to approve with a passkey in the browser (if the account has one),
#   or type the code from the authenticator app
# → Pins the server's host key on the first connect (the API lists it, so nothing is asked)
# → Mounts ~/cryptstorage

# Status
cryptclient status

# Version
cryptclient version

# Disconnect
cryptclient disconnect
# or: remove the USB stick → automatic umount

# The padlock icon that stays running (Linux: in the panel; Windows: CryptStorage.exe next to the clock)
cryptclient tray
```

---

## USB stick layout

The key is kept in the hidden folder `.secdisk` on the stick's own file system (FAT32, exFAT or NTFS),
the same on Linux and Windows, so one stick works on both:

```
.secdisk/key.bin            The encrypted SSH key blob (format v3, sealed with the stick secret)
.secdisk/serial.bin         Serial number HMAC-SHA256 as Windows reads the serial
.secdisk/serial-linux.bin   ... as Linux reads it (serial-darwin.bin on macOS)
```

Each OS reads a stick's serial number its own way, so each keeps its own binding: a stick prepared on
Windows is bound on Linux at its first use there, and the other way round (the client says so). A
binding this OS made is never replaced; a copy on another stick is refused.

`init-usb` (and `setup`) needs no `sudo` on Linux: the desktop has mounted the stick, or the client mounts
it with `udisksctl`. A stick with no file system that can be opened is erased and formatted first (one
FAT32 partition, needs `mkfs.vfat` from `dosfstools` and `sudo`); you confirm by typing the device name
(e.g. `sdb`), and everything on it is lost.

**Sticks prepared on Linux by older versions** keep their key in raw sectors 1 MiB into the stick
(magic `CRYPTKEY` at sector 2048, the key from sector 2049, the serial binding at sector 2054, in a gap
before the first partition). They keep working on Linux, but not on Windows. Preparing such a stick again
(`init-usb`, or `setup` when it asks) moves the key into `.secdisk` and clears the raw sectors. That gives
the stick a new SSH key, which takes effect after the server's safety wait (24 h by default).

The stick's file system also stores: `cryptstorage.hostkey` (the pinned SSH host key),
`cryptstorage.certpin` (TLS pins), `cryptstorage.escrow` (the accepted escrow setting),
`cryptstorage.server` (the server the stick belongs to) and the backup made by the `upgrade-key` command.

**One stick, one server.** A stick belongs to the server it was prepared for: its key opens only with
that server's stick secret. The stick notes the server's address and `server_id` (from `/server-info`) in
`cryptstorage.server`, and `connect`, the tray, `init-storage`, `change-password` and `recover` stop before
the password is asked when the computer is set to another server. `setup` offers to prepare such a stick
for the new server, which ends its use on the old one. The `server_id` is derived from the server's
`TOTP_ENCRYPTION_KEY`, so it changes only when the stick secrets are lost too; a new address or a
reinstall with new SSH host keys keeps it. The key on a stick is sealed only after an SFTP login with it
worked, so a client set to the wrong server cannot tie the stick to it. `cryptclient diagnose` shows the
stick's server next to the configured one, and the tray menu shows the server it uses.

---

## Security

| Property | Description |
|---|---|
| Host key pinning | The API lists the SFTP service's host keys over the pinned TLS connection, so the client pins the right key without asking; a key the API does not list is refused. Only a server that does not report its keys falls back to asking on the first connect. The key is stored on the stick's file system **per host**. |
| TLS pinning | The pin is the server's **public key** (`sha256/<base64>`), not the leaf certificate: it survives certificate renewals as long as the key stays the same (`certbot --reuse-key`). There can be several pins (comma-separated or on separate lines); one match is enough, so a pin of the CA's intermediate certificate works as a backup pin. The pin is checked in addition to the normal certificate verification, not instead of it. An invalid pin blocks the connection (it does not silently disable pinning). The old 64-character leaf certificate fingerprint still works. |
| Serial number binding | The SSH key is bound to the stick's serial number with an HMAC. Serial numbers can be cloned, so this is not a strong protection; the real protection is the password. |
| Key encryption | **Argon2id** (3 passes, 64 MiB, 4 threads) + AES-256-GCM. A wrong password reveals nothing. Old PBKDF2 keys still work; upgrade them with `cryptclient upgrade-key`. |
| Key only in memory | The decrypted SSH key is held in the process's own ssh-agent (Unix socket in a 0700 directory), not in a file. `sshfs` can therefore reconnect after a network interruption. (Windows uses a temporary key file, because SSHFS-Win cannot use the agent; it is deleted as soon as the drive is up, so there is no automatic reconnect there.) |
| Automatic umount | Removing the stick or pressing Ctrl+C unmounts the storage and closes the agent. |
| StrictHostKeyChecking | sshfs uses `StrictHostKeyChecking=yes` against the pinned host key. |

---

## Encryption (crypto/unlock.go)

- **Argon2id** as the key derivation function; the parameters are stored in the blob and authenticated (AES-GCM AAD)
- **AES-256-GCM** for encryption + integrity checking
- Format v2: `"CSK2" | time(4) | memory KiB(4) | threads(1) | salt(32) | nonce(12) | ciphertext+tag`
- Format v3, sealed: `"CSK3" | time(4) | memory KiB(4) | threads(1) | stick id(16) | salt(32) | nonce(12) | ciphertext+tag`,
  key `HKDF-SHA256(Argon2id(password) || stick secret)`. The server keeps the stick secret and releases it only
  after the full login, so a lost or copied stick cannot be attacked offline; removing the stick in the web UI
  makes its key unusable. `connect`, `setup` and `init-storage` seal an older key automatically.
- Format v1 (legacy, still readable): `salt(32) + nonce(12) + ciphertext + tag` with PBKDF2-SHA256 200,000 it.
- Upper limits apply to the parameters when reading: a blob coming from the stick cannot force an allocation of gigabytes

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CRYPTSTORAGE_SERVER` | asked once by `setup` / `connect` | API server URL. The answer is saved in the settings file (`~/.config/cryptstorage/env`, on Windows `%AppData%\cryptstorage\env`); a value in the environment wins |
| `CRYPTSTORAGE_CERT_PIN` | the stick's `cryptstorage.certpin` | Comma-separated TLS pins: `sha256/<base64>` or a leaf certificate fingerprint |
| `CRYPTSTORAGE_MOUNT` | `~/cryptstorage` | Local mount directory |
| `CRYPTCLIENT_DEVICE` | – | Device path (set automatically by the udev rule's user service) |
| `CRYPTCLIENT_SYNC_DIR` | – | Synchronised folder; setting it turns syncing on (also for the tray) |
| `CRYPTCLIENT_SYNC_INTERVAL` | `60` | Seconds between synchronisations (at least 10) |

---

## Installer packages

### Linux (Ubuntu/Debian)
```bash
cd packaging && ./build-all.sh 1.0.0
sudo apt install ./packaging/linux/dist/deb/cryptclient_1.0.0_amd64.deb
```
Installs the binary, the udev rule and the desktop file automatically.

### Linux (Fedora/RHEL)
```bash
cd packaging/linux && ./build-rpm.sh 1.0.0
sudo rpm -i dist/cryptclient-1.0.0-1.x86_64.rpm
```

### macOS
Run `packaging/macos/build-pkg.sh` on a macOS machine.
Produces a universal binary package (.pkg) that includes
a LaunchAgent and a dependency installer script (macFUSE + sshfs).

### Windows
CI builds `CryptStorageSetup.exe` from `packaging/windows/cryptstorage.iss` (Inno Setup, see the `installer`
job in `.github/workflows/windows.yml`). It installs the client, then runs `cryptclient install-deps`,
which downloads Dokan, WinFsp and SSHFS-Win from their official release pages and checks pinned SHA-256
values (`deps/deps.go`); cppcryptfs is added on the first `cryptclient setup`. Not yet code-signed.

---

## Linux udev autostart

```bash
sudo udev/install-udev.sh
echo 'CRYPTSTORAGE_SERVER=https://storage.example.com' > ~/.config/cryptstorage/env
```

When a USB stick is plugged in, the udev rule starts `cryptstorage-tray@<device>.service` in the users'
systemd. The service waits until the desktop has mounted the stick and stops without a word when there is
no `.secdisk` folder on it (for an older raw-sector stick the rule checks the marker itself and gives the
user at the seat access to the stick). It asks for the password (and the
username the first time; it is remembered in `~/.config/cryptstorage/username`) in zenity dialogs and
opens the storage. Removing the stick disconnects. Other USB disks are not touched.

Needs a desktop session whose environment the user's systemd knows (GNOME and KDE pass `DISPLAY` /
`WAYLAND_DISPLAY` to it) and `zenity`. Log: `journalctl --user -u 'cryptstorage-tray@*'`.
When the tray icon below is running, the service leaves the stick to it.

## Linux tray

`cryptclient tray` (the "CryptStorage" entry in the application menu) puts a padlock in the panel's tray area
and stays running, like `CryptStorage.exe` on Windows: grey when the storage is closed, amber while connecting,
green and open when connected. Plugging in the stick (or having it in at start) asks for the password in
zenity dialogs; the menu connects and disconnects, opens the storage and synchronised folders and the
account web page, turns starting at sign-in on or off (`~/.config/autostart/cryptstorage-tray.desktop`, on
after the first start) and opens `cryptclient setup` in a terminal. `cryptclient setup` starts it at the
end. Log: `~/.cache/cryptstorage/tray.log`.

The icon is a StatusNotifierItem over the session D-Bus (package `sni`, no GTK or cgo). KDE, Xfce,
Cinnamon, LXQt and Ubuntu's GNOME show it; plain GNOME (e.g. Fedora) needs the AppIndicator extension, and
without a tray area the tray says so once and still asks for the password when the stick is plugged in.
Without a desktop or zenity, `cryptclient tray` falls back to the terminal.

## Windows tray

`CryptStorage.exe` is the same program built as a window program (`go build -ldflags=-H=windowsgui`); the
installer puts it next to `cryptclient.exe` and in the Start menu. It shows a padlock next to the clock:
grey when the storage is closed, amber while connecting, green and open when connected. When a CryptStorage
stick is plugged in (or is already in at sign-in) it asks for the password, and the username and
verification code when needed, in small windows; for a passkey the code is left empty and the browser
opens. Removing the stick or choosing Disconnect closes the storage. The menu also opens the storage
and synchronised folders, turns starting at sign-in on or off (`HKCU\...\Run`, on after the first
start) and opens the console setup. Everything it prints goes to `%LOCALAPPDATA%\cryptstorage\tray.log`.

The windows are made with the Win32 API directly (package `wingui`), so the client stays pure Go
(`CGO_ENABLED=0`) without a GUI library. Helper programs (PowerShell, rclone, cppcryptfsctl) are started
without console windows (package `nowindow`). The exe's own icon and version information come from
`go run ./packaging/windows/winres`, which writes `rsrc_windows_amd64.syso` (drawn by the same code, so no
image files are kept; the build scripts and workflows run it before building for Windows).

## Synchronised folder

`cryptclient connect --sync` (or `CRYPTCLIENT_SYNC_DIR=/path` in `~/.config/cryptstorage/env`, which also
works for the tray) keeps a local folder, `~/CryptStorage` by default, in step with the storage while it is
connected. Files in it can be used offline; removing the stick stops syncing and leaves the folder as it is.

- **rclone bisync** does the work, every 60 seconds (`CRYPTCLIENT_SYNC_INTERVAL`). The client uses its own
  copy of rclone 1.71.1, downloaded on first use from rclone's GitHub release and checked against a fixed
  SHA-256 (into `~/.local/share/cryptstorage/bin` or `%LOCALAPPDATA%\cryptstorage`); a newer rclone (1.66+) on
  `PATH` is used if present.
- **One device at a time.** Before each run the client takes the volume's sync lock from the API and
  renews it while rclone runs; another device waits. Without the lock two devices syncing at once lose files
  (docs/design-features.md section 5.1).
- **Conflicts:** a file changed on two devices between runs is kept twice, as `name.conflict1` and
  `name.conflict2`.
- **Safety stops:** the first sync needs an empty or new folder (nothing local is overwritten); if more than
  half of the files were deleted on one side, nothing is synchronised until you confirm once with
  `connect --sync --allow-mass-delete`.
- **It is a mirror, not a backup.** Whatever happens in the storage reaches the folder: a file deleted there,
  or an older version put back, is deleted or rolled back here too (also by a faulty or malicious server,
  SECURITY.md). So that this never destroys a local file outright, every local file that a run deletes or
  replaces because of the storage is first moved to `.secdisk-trash/<date_time>/` inside the folder and kept
  for 30 days (the client says when that happens). Keep a real backup of the folder as well.
- **A file that cannot be read** in the storage (damaged, or changed on the server) does not stop syncing:
  the client names it, keeps the local copy, leaves the file out and carries on with the rest. It is synced
  again once it reads again or is gone from the storage; `connect --sync --replace-unreadable` replaces it
  with the local copy.
- **An interrupted run** (the client ended or a run failed half way) is followed by a full comparison: the
  newer version wins where the two sides differ (the replaced local file goes to the trash), and files deleted
  just before may come back. Nothing is lost.
- The volume gets a small `.secdisk-sync` file; rclone refuses to work with an empty folder.
- **The local copy is not encrypted by CryptStorage.** The server only ever holds ciphertext; the files in the
  synchronised folder are as safe as the computer's own disk. When syncing starts, the client checks the
  folder's disk (LUKS/dm-crypt on Linux, BitLocker on Windows, FileVault on macOS) and warns if it is not
  encrypted. `cryptclient diagnose` shows the result.

Tested in CI with two devices syncing at once: on Linux through the real API, SFTPGo, sshfs and gocryptfs; on
Windows through SSHFS-Win and cppcryptfs drives (`TestSFTPSync`, without the API). On Windows, SSHFS-Win runs
with `-o cache=no` for the same reason as `dir_cache=no` on Linux.

---

## Operating system requirements

Minimum supported systems: Windows 10, current macOS, current Linux distributions. Windows 7 and 8 are not supported.

| OS | Requirement | Installation |
|----|-------------|--------------|
| Linux | gocryptfs, sshfs, fuse3 (zenity for the dialogs) | Dependencies of the .deb/.rpm package |
| macOS (untested) | macFUSE, sshfs, gocryptfs | the .pkg's `install-deps.sh` installs macFUSE and sshfs only; gocryptfs by hand |
| Windows | Dokan, WinFsp, SSHFS-Win, cppcryptfs | Installed by `CryptStorageSetup.exe` or `cryptclient install-deps` |
