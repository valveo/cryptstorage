# Design proposal: customised setup app for the USB key stick

Status: **proposal; the graphical wizard is not implemented.** Written 2026-10-22 after the security and
usability review. Since then (2026-10-29): `cryptclient setup` does the whole flow in a terminal, Windows has an
unsigned Inno Setup installer and the tray `CryptStorage.exe`, the SSH host keys come from the API over the pinned TLS
connection, and the key on the stick is also sealed with a server-held stick secret. Sections 3–7
are the original proposal; where they differ from what was built, a note says so.
Related: [design-e2ee.md](design-e2ee.md) (goal G6, access only through the client and the stick).

## 1. Why

When this was written, preparing a stick took a terminal, an environment variable for the server address, a
hand-partitioned stick (first partition at sector 4096) and a copy-and-paste of the public SSH key into
the web form. Now (2026-10-29) `cryptclient setup` (terminal) walks through account, stick and storage on Linux and Windows,
asks for the server address once and saves it (on Windows the key is a file on the stick's drive, see design-e2ee.md
section 15). On Windows the menu of the tray `CryptStorage.exe` opens this terminal setup;
macOS device listing is still missing and a graphical wizard is not built. TLS and host-key pins are kept on the stick where its drive is known.
Users are expected to be non-technical, so this has to become one guided step.

## 2. Goals and non-goals

**Goals**

- S1. A user downloads one file, opens it, answers a few questions, and ends with a working stick.
- S2. The server address, TLS pin, SSH host-key fingerprint and an invitation code arrive inside the
  download, so the user never types or confirms any of them.
- S3. The private key is generated on the user's computer and never leaves it unencrypted. It is not in
  the download, not in an image and not on the server.
- S4. The public key is registered with the server by the setup app, using the invitation code.
- S5. The stick also carries the portable client, so it can be used on any supported computer without
  installing anything.
- S6. Supported systems: Windows 10 or newer, current macOS, current Linux.

**Non-goals**

- A raw disk image to be copied onto the stick (see section 8).
- Hiding the fact that the stick is erased: the app says so and asks for confirmation.

## 3. User flow

1. The user receives an invitation (e-mail or admin page) with a link to their personal setup download.
2. They open the file. The OS asks for administrator rights; the app explains why. (As built on Windows the
   key is a file on the stick's own drive, so no administrator rights are needed, and the client refuses to
   run elevated because SSHFS-Win cannot write then. Linux does the same since 2026-10-30, also without
   administrator rights, so one stick works on both.)
3. The app lists removable USB devices only, with model and size, and refuses internal disks.
4. The user picks the stick and confirms "This erases everything on the stick".
5. The user chooses a password (at least 12 characters, strength hint) and repeats it.
6. The app partitions the stick, writes the encrypted key, writes the configuration and pins, copies
   the portable client, registers the public key, and shows "Done. Keep the stick safe."

Every error message is a plain sentence with one suggested action. No technical text is shown by default;
a "details" button reveals it for support.

## 4. The configuration bundle

The download embeds a signed configuration:

| Field | Purpose |
|---|---|
| `server_url` | API address, replaces `CRYPTSTORAGE_SERVER` |
| `tls_pin` | Public-key pin(s), `sha256/<base64>` |
| `ssh_host_key` | SSH host-key fingerprint, so no trust-on-first-use prompt (no longer needed: the API hands the host keys out over the pinned TLS connection) |
| `invite` | Single-use code that authorises registering one public key |
| `username` | Pre-filled, stored on the stick so it is never typed again |
| `expires` | The invitation and the download stop working after this time |

The bundle is signed with a server-side signing key whose public half is compiled into the app, so a
tampered bundle is refused. The pins are copied to the stick's FAT32 partition; the app never relies on
the OS temp directory.

## 5. Server side

- Admin or self-service page "Create invitation" produces a single-use code with an expiry.
- `POST /enroll` takes the invitation code and the public key. It binds the key to the account and
  burns the code. It is rate limited and audited like the other account endpoints.
- A download endpoint builds or patches the app with the bundle for that invitation.
- Replacing a key later (lost stick) needs a new invitation and an e-mail confirmation with a delay, in
  line with the review finding that the password alone must not be enough to take over an account.
  (Built without invitations: a new SSH key needs the full login and waits `change_delay_hours`, default
  24 h, with an e-mail and a cancel link.)

## 6. Security

- The setup app is the root of trust: a forged copy would receive the password. It must be served only
  over the pinned HTTPS site, be code signed, and its checksum is published.
- The password is typed into the app only. It is never put on a command line (the review found the old
  wizard would have used `--password`).
- The device picker lists removable devices only and re-checks the chosen device immediately before
  writing.
- The stick stays two things together: the key (a file in the stick's `.secdisk` folder) and the password,
  plus the stick secret the server releases after the full login. The app does not weaken the
  Argon2id protection of the key blob.
- The invitation code is single use, short lived and tied to one account.

## 7. Platforms and signing

| Platform | Raw access | Notes |
|---|---|---|
| Windows 10+ | UAC elevation, `\\.\PhysicalDriveN` | Authenticode signing needed to avoid SmartScreen warnings |
| macOS | `sudo`-style prompt, `/dev/rdiskN` | Developer ID signing and notarisation needed |
| Linux | `pkexec` | AppImage or static binary |

Code signing certificates cost money each year; check current prices before committing to a release plan.
Decided since: no paid signing. Windows via SignPath's free open-source programme once the repository is
public; releases carry checksums ([verify-release.md](verify-release.md)); macOS is out for now
because Apple's developer account costs 99 USD a year.
Builds are cross-compiled with Go; signing happens in CI where the credentials live.

## 8. Alternatives considered

- **A disk image written with `dd` or similar.** Rejected: the key must be created on the user's machine,
  an image fits only one stick size, writing it needs raw access with a high risk of choosing the wrong
  disk, and an image cannot carry per-user data.
- **Keep the command-line `init-usb`.** Stays for administrators and tests, but is not the user path.
- **Let the server generate the key.** Rejected: the server would then hold a private key.

## 9. Test plan

- Unit: bundle signature check, invitation handling, device filter (internal disks refused), partition
  layout calculation, error-message mapping.
- Integration on Linux in CI with a loop device: full setup, then `connect`.
- Manual on Windows and macOS with real sticks before each release (not automatable in CI).
- Adversarial: tampered bundle, expired and reused invitation, wrong device selected, stick removed
  halfway, cancelled elevation prompt.

## 10. Plan

| Phase | Work |
|---|---|
| 0 | Spike: partition and write a stick on Windows and macOS from Go without external tools |
| 1 | Bundle format, signing, `/enroll` and invitation endpoints |
| 2 | Setup app core (device picker, partitioning, key write, pins, registration) on Linux, with tests |
| 3 | Graphical front end and Windows and macOS ports |
| 4 | Signing and notarisation in CI, download page, documentation |

## 11. Open questions

1. Build one app per invitation, or one app plus a separate small bundle file the user opens with it?
2. Who creates invitations: administrators only, or self-service after sign-up?
3. ~~Which signing certificates to buy, and who holds them?~~ None bought: SignPath (free for open source) for Windows; macOS postponed.
4. Which GUI approach for Go on all three systems (native dialogs, a small web view, a toolkit)?
5. Should the portable client on the stick also self-update?
