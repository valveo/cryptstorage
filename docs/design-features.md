# Design proposal: sharing, sync, offline use, mobile and browser access

Status: **partly implemented.** Sync and the offline decisions (section 5) are done (2026-10-26); shared
folders are planned for v0.2 ([design-sharing.md](design-sharing.md)); the rest is a proposal. Written
2026-10-24 after comparing CryptStorage with Proton Drive.
Related: [design-e2ee.md](design-e2ee.md), [design-setup-app.md](design-setup-app.md),
[design-stick-pin.md](design-stick-pin.md).

## 1. Why

CryptStorage today is one encrypted volume per user, mounted over SSHFS from our own client. Companies that
would run their own server expect more: shared folders, a synchronised local copy, offline use, a phone
app and some kind of browser access. This document lists the options for each, what each depends on,
and a suggested order. Nothing here is decided.

Constraints that carry over from earlier decisions:

- **Windows is required** (Windows 10 or newer). Every client feature must work there.
- **The project targets companies running their own server**, so administration must stay simple.
- **Access is meant to go through our own client and the USB stick** (design-e2ee.md, goal G6). Browser
  and phone access pull against this; section 7 treats that openly.
- The licence is AGPL-3.0-only, so any component we embed must be compatible with it.

## 2. The decision everything depends on (decided)

**Decided: client-side encryption, for everything.** It is the only mode since 2026-10-25 (design-e2ee.md
section 14), and shared folders stay end-to-end encrypted as well (2026-10-26, design-sharing.md). What
that means for each feature:

| Feature | With client-side encryption |
|---|---|
| Sharing | The folder key is wrapped separately for every member's public key (design-sharing.md) |
| Browser | Decryption must run in the browser (JavaScript or WebAssembly) |
| Mobile | The app decrypts on the phone |
| Removing a member | Access is cut by the server at once; the folder key is rotated afterwards |
| Gateway | Passes ciphertext only; it never needs a key |

## 3. Foundation: device credentials and an HTTP file gateway

Two pieces are needed by most features:

- **Device credentials.** Phones and browsers cannot use the USB stick. A device gets its own key,
  stored in the platform's secure storage (Android Keystore, iOS Secure Enclave, Windows or macOS
  keychain), enrolled by an already authenticated computer with a QR code or an invitation. The stick
  becomes one kind of credential among several; lost devices are revoked individually.
- **An HTTP file gateway.** Phone and browser clients cannot use SSHFS. A gateway offers authenticated
  HTTPS access (WebDAV, or a small REST API with chunked uploads) in front of the same storage. SFTPGo
  already offers SFTP, WebDAV and HTTPS with share links. **Decided:** SFTPGo (section 9, question 6); it
  already serves the SFTP storage, run unmodified, and AGPL-3.0 matches CryptStorage's licence.

## 4. Sharing

Decided 2026-10-26: shared folders are end-to-end encrypted. Detailed design: [design-sharing.md](design-sharing.md).

- **Shared folders for groups.** A shared volume belongs to a group. Members have admin, read or write
  roles. Roles are enforced by the gateway or file server, so a read-only member cannot change data.
- **Key handling.** The volume key is wrapped for each member's public key, as Proton does (the
  server-side variant was dropped with the server-side mode).
- **Removing a member** cuts access on the server at once and requires re-keying afterwards.
- **Links for outsiders** (read-only, password, expiry) need the gateway and a web page, so they depend on
  section 7.
- Each user is one SFTPGo virtual user with one directory; shared folders need their own volumes and
  access rules in SFTPGo (design-sharing.md).

## 5. Synchronisation and offline use

The network mount works only while connected. A synchronised local folder works offline.

| Option | Idea | Notes |
|---|---|---|
| A. Use an existing sync tool | rclone (sync or bisync) over SFTP or WebDAV | Fast to build, careful with conflict handling and licence checks |
| B. Own sync engine in the Go client | Watch the folder, compare, upload and download | Full control, largest effort |
| C. Windows files-on-demand | Cloud Files API placeholders like OneDrive | Best Windows experience, large and platform specific |

**Decided and built:** option A, rclone bisync (section 5.1). The original suggestion was option A or a small version of B with a simple rule: if both sides changed a file, keep
both and name the second copy with the user and time. Offline use then means "make this folder available
offline", which keeps a full local copy.

Offline decisions (2026-10-26):

- **The client does not encrypt local copies.** CryptStorage's promise is that the *server* only holds
  ciphertext; how files are stored on the user's own device is the device's responsibility (a compromised
  or lost client is already outside the threat model, SECURITY.md). Decided as well: the client checks
  whether the computer's disk encryption (BitLocker, LUKS, FileVault) is on and warns if it is not, so
  users do not read "encrypted storage" as "my laptop is protected". **Implemented** (2026-10-26, package
  `cryptclient/diskenc`): the warning is shown when syncing starts and in `cryptclient diagnose`. The
  check needs no administrator rights and says "unknown" rather than guessing (network or FUSE folders).
- **Removing the stick ends the connection** (as the Linux tray already does). The offline copy stays on
  the device; removing the stick stops syncing, it does not hide local files.
- **Network drops do not need a new login** while the session lasts: sshfs reconnects with the key held in
  memory. Proposal for when a device-bound key and TOTP replace the stick (design-factors.md tier 2): TOTP
  is asked when a session starts; the session lasts until logout, device restart or a time limit (for
  example 12 hours), and reconnects after a network drop are silent.

### 5.1 Sync spike: rclone bisync (2026-10-26, Linux)

**Status: implemented** (2026-10-26): API sync lock (`POST`/`DELETE /storage/sync-lock`, lapses after
`SYNC_LOCK_SECONDS`, default 120), the client's `syncer` package and `connect --sync`; see
cryptclient/README.md. Tested on Linux, including the CI integration test with two devices syncing at
once through the real API, SFTPGo, sshfs and gocryptfs. On Windows it is tested in CI
over SSHFS-Win and cppcryptfs (two devices, in-process lock; SSHFS-Win needs `cache=no`). The spike that led
to it follows.

Setup: rclone 1.71.1 `bisync` between a local plaintext folder and the mounted plaintext view of a
gocryptfs volume (gocryptfs 2.4.0 `-sharedstorage` on sshfs 3.7.3), two "machines" on one ciphertext
directory, OpenSSH on the same host. Script: `scripts/spikes/sync_bisync.sh`. Options used:
`--compare size,modtime,checksum --resilient --recover --max-lock 2m --conflict-resolve none
--conflict-loser num --modify-window 1s --create-empty-src-dirs`.

| Test | Result |
|---|---|
| A adds files and a directory, A then B syncs | B gets them |
| Both edit the same file between syncs | both kept as `name.conflict1` and `name.conflict2` on both machines, nothing lost |
| B deletes a file | deleted on A |
| A edits a file that B deleted | the edit wins, the file comes back on B |
| 1000 small files | upload 7 s, download 8 s, unchanged scan 4–5 s (local network; slower over the internet, not measured) |
| **A and B sync at the same moment, no lock** | **in 8 of 8 rounds one machine's new file vanished without a conflict copy** |
| A and B sync at the same moment, with a server-side lock | 0 of 8 rounds lost anything; both trees identical |
| Sync killed in the middle | after the stale lock expires, the next run recovers; files identical, `gocryptfs -fsck` clean |

Two settings were required, otherwise sync did not work at all:

- **sshfs `-o dir_cache=no`.** With sshfs's default directory cache, B did not see A's new files for up to
  20 seconds and silently skipped them; worse, it could overwrite a change it had not seen yet.
- **`--modify-window 1s`.** SSHFS reports whole seconds, so without it every file looked changed and
  rclone's safety check stopped every run.

Conclusions:

- **rclone bisync is good enough for a first version**, with the sync folder replacing the live mount
  for everyday use. rclone writes to a temporary name and renames, which avoids the file corruption seen
  with two live mounts (design-sharing.md section 5).
- **A lock per synchronised volume on the server is mandatory.** rclone's own lock is local to one
  machine. A directory created with `mkdir` in the ciphertext directory works (atomic over SFTP); it needs
  an owner and an expiry so a crashed client does not block the others. With one user and several
  devices the same lock is needed.
- Windows was checked afterwards (CI over SSHFS-Win and cppcryptfs, and by hand with a real stick,
  2026-10-28); rclone ships with the client (about 60 MB, MIT licence). Still to check: a real internet
  connection (each SSHFS `stat` costs a round trip, so a scan of many files will be much slower) and large files.
- If scanning speed becomes the problem, the next step is to let rclone talk SFTP directly and keep only
  a local gocryptfs view, or an own engine (option B).
- **Built after the tamper tests (2026-10-29).** The folder mirrors the storage, so a deletion or an
  older version put back on the server reaches it. rclone's `--backup-dir1` moves each local file a run
  deletes or replaces into `.secdisk-trash/<run>/` in the folder (excluded from syncing, kept 30 days).
  A storage file that cannot be decrypted made rclone stop and lose its listings; the client now reads the
  file names from rclone's errors, puts any local file rclone had already moved aside back, leaves those
  files out (`--exclude-from`) and compares both sides in full at once (`--resync-mode newer`). Listings
  left as `.lst-err` by an interrupted run get the same full comparison instead of the old "rename the
  folder" advice.

## 6. Mobile

- Needs device credentials and the gateway (section 3); iOS cannot mount SSHFS or use raw sectors.
- Scope for a first version: browse, download, upload (including photos) and offline marking, no editing.
- A native app per platform is the most capable; a web app is cheaper but weaker offline and in key storage.
- The phone key lives in secure hardware and unlocks with the device's biometrics or code. Lost phones are
  revoked on the server.

## 7. Browser access (needs a decision)

An earlier requirement says the web interface must not allow browsing stored files and that access goes
only through the client and the stick. Browser access conflicts with that, because a browser has no USB
stick and would rely on the password and perhaps a second factor.

Options:

1. **No browser access** (current rule). Mobile and desktop clients only.
2. **Limited browser access:** download via links that were explicitly created in the client, no browsing.
3. **Full browser access as an organisation policy,** off by default. An administrator turns it on, and it
   requires a second factor (WebAuthn passkey or one-time code) so the password alone is not enough.

**Decided 2026-10-26: option 3** (section 9). Note for when it is built: decryption in the browser runs
JavaScript the server serves, so a malicious server could take the password or the keys; the same limit
as the web UI's password form. Users who need protection from the server keep using the client.

Option 3 fits companies best but changes the security model; the document design-e2ee.md would need the
goal G6 reworded. With client-side encryption it also needs decryption in JavaScript.

## 8. Suggested order

| Step | Work | Depends on | Effort | Status (2026-10-29) |
|---|---|---|---|---|
| 1 | Shared folders for groups, roles and member removal | Mounting model | Large | planned for v0.2 |
| 2 | Device credentials and HTTP gateway | Step 1 optional | Large | later |
| 3 | Mobile app: browse, upload, download | Step 2 | Large | postponed far |
| 4 | Sync, then offline marking | Step 2 or the existing mount | Large | sync done over the existing mount; offline marking later |
| 5 | Browser access as an organisation policy (option 3, decided) | Step 2 and a second factor | Medium | later |

## 9. Open questions

1. ~~Server-side or client-side encryption first?~~ Client-side, for everything (section 2).
2. ~~Which browser option in section 7?~~ Option 3 (decided 2026-10-26): an operator policy, off by default.
   With client-side encryption the browser must implement the gocryptfs format itself (WebAssembly) and
   relies on the password and a second factor instead of the stick, so it comes after sync and sharing.
3. ~~Sync tool or own engine?~~ rclone bisync for the first version, with a server-side lock per volume
   (decided 2026-10-26 after the spike in section 5.1); an own engine only if speed over the internet or
   Windows proves it too limited.
4. ~~Should the offline copy be encrypted by the client?~~ No (section 5).
5. ~~Native mobile apps, or a web app first?~~ Postponed to the distant future (decided 2026-10-26). It
   needs device credentials and the gateway first, and the app must read the gocryptfs format itself.
6. ~~Which gateway: SFTPGo, or our own small service?~~ SFTPGo: it already stores the data and has WebDAV
   built in, and with client-side encryption the gateway only passes ciphertext.
