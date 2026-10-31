# Design proposal: client-side encryption

**Status:** implemented on Linux and Windows, the only mode (2026-10-25), see section 15 · **Date:** 2026-10-21

*This document was written before the change: "today" in sections 1–13 means the old server-side mode.
Notes marked **As built** say where the result differs from the proposal; section 15 is the current state.*

Today CryptStorage encrypts on the **server**: the API unwraps a user's master key at login and the
root daemon mounts the decrypted volume. This document proposes moving the encryption to the
**client**, so that the server stores only ciphertext and never sees a key or a plaintext file.

Everything under "Facts about gocryptfs" was either taken from gocryptfs's own documentation (linked
at the end) or checked by running gocryptfs 2.4.0; where something could not be checked it says so.

---

## 1. Why

What the server can see today (see [SECURITY.md](../SECURITY.md)):

| | Server sees it? |
|---|---|
| Account password | yes, in memory at every login |
| Master key | yes, from login until the mount, and in the daemon while mounting |
| File contents | yes, plaintext, for as long as the user's storage is mounted (host FUSE mount and the user's container) |
| File sizes, counts, timestamps, client IPs | yes |

So the current design protects against stolen disks, database dumps and backups, but **not** against
a compromised or malicious server (root on the host, code execution in the API or daemon, an
administrator). The weaknesses that remain in the server-side model (a root daemon with Docker access,
one published SSH port and container per user, a master key held in a Python process) are
all consequences of the server having to handle keys.

## 2. Goals and non-goals

**Goals**

- G1. The server never holds a key or plaintext. A fully compromised server learns file sizes and
  access patterns, nothing else, and cannot read or silently alter file contents.
- G2. Data stays recoverable without the server's help (recovery code).
- G3. Keep the **gocryptfs on-disk format**: existing volumes can be migrated, standard tools keep working.
- G4. A smaller, unprivileged server: no root daemon, no Docker socket, no per-user containers or ports.
- G5. Keep what does not need plaintext: accounts, SSH keys, quotas, rate limiting, audit log, backups.
- G6. Every access requires at least two different factors (something you know, something you have,
  something you are); the password alone is never enough. A USB stick is one allowed "have" factor, not
  the only one; others are a device-bound key, a phone one-time code and a hardware key. The server
  operator chooses which combinations are accepted. See [design-factors.md](design-factors.md). The SSH
  key is never a readable file; it is unlocked into the client's memory or stays in secure hardware. By
  default the web UI shows account information only (login details, disk usage, password change and
  similar) and does not list or browse stored files; whether browser access can be enabled as an
  operator policy is an open decision (design-features.md section 7). Ordinary SFTP clients
  are not a supported way in. This is a usability and deterrence property, not a cryptographic one: the
  client is open source, so someone holding the needed factors can use their own tooling. Section 4.2
  must not weaken this: a generic SFTP server on the server side is acceptable only because it exposes
  ciphertext and accepts only keys enrolled for the account.

**Non-goals**

- Hiding metadata: file sizes, number of files, timestamps and permissions are visible to the server
  (gocryptfs does not hide them).
- Integrity against a *malicious* server (rolling files back, deleting files, swapping files). gocryptfs
  does not provide it; see section 10 for what can be added later.
- Web or mobile access to plaintext (including file browsing in the web UI), and sharing between users.
- Support for operating systems the client toolchain no longer supports. The minimum is Windows 10 (Windows 7 and 8 are not supported: current Go releases dropped them, and the OS no longer receives security updates), plus current macOS and Linux versions.
- Protection against a compromised client machine.

## 3. Facts about gocryptfs that shape the design

**From its documentation** (links at the end)

- File contents: AES-256-GCM per block; file names: AES-EME. Each file has a random file ID that is part
  of every block's authentication data.
- The master key lives in `gocryptfs.conf`, wrapped with a key derived from the passphrase by scrypt.
  The scrypt parameters are stored in the file.
- Threat model page: plaintext file sizes can be computed from ciphertext sizes (gocryptfs's older
  security notes also list owner, permissions and timestamps as not hidden); **file content is not tied to the file name**, so whoever controls the
  ciphertext can rename a file to another valid encrypted name; the per-directory `gocryptfs.diriv`
  can be replaced by a copy from another directory. We found no claim of protection against replacing a
  file with an older valid version or deleting files, so this design assumes there is none.
- Platforms: Linux is native; macOS support is described as beta (macFUSE); on Windows an independent
  reimplementation, cppcryptfs, reads the same format.

**Checked by running gocryptfs 2.4.0** (init, `-passwd`, `-fsck`: none of these needs FUSE)

| # | Observation | Consequence |
|---|---|---|
| F1 | `gocryptfs.conf` is ~400 bytes and carries `ScryptObject` (salt, N, R, P) | The scrypt cost is not an environment setting any more: the `SCRYPT_N_POW` hazard of today's design disappears. |
| F2 | `gocryptfs -init -masterkey=<hex>` works: **the client can choose the master key itself.** The passphrase is then asked on the terminal. | The client knows the master key from the start and can build the recovery code without the server. |
| F3 | `-masterkey` cannot be combined with `-passfile` or `-extpass`. | `init` and `-passwd` with a master key must be driven through a pseudo-terminal, or the config must be written by our own code. |
| F4 | A non-terminal `-init` prints "suppressing master key display". | Another reason to generate the key ourselves instead of reading it from gocryptfs's output. |
| F5 | `gocryptfs -passwd -masterkey=<hex>` replaces the passphrase **without knowing the old one**, keeping the old config as `gocryptfs.conf.bak`. | This is the recovery primitive. |
| F6 | gocryptfs does **not** check that the master key given to `-passwd` is the right one. With a wrong key the config was overwritten and `-fsck` with the new passphrase then reported "1 corrupt files". `-fsck -masterkey` on an *empty* volume accepted a wrong key. | Recovery must verify the key itself before writing (section 6.5). |
| F7 | Mounting with the passphrase from a file or stdin works (it is how `cryptdaemon` mounts today). | `connect` needs no new mechanism. |

## 4. Proposed architecture

```
  user machine                                         server
 ┌───────────────────────────────────┐                ┌──────────────────────────────┐
 │ cryptclient                       │   HTTPS        │ nginx ─┬─ web UI (accounts, keys) │
 │  ┌───────────┐  ┌───────────────┐ │───────────────▶│        └─ /api  (FastAPI)         │
 │  │ USB stick │  │ passphrase    │ │  account login │             │ cryptdaemon → REST  │
 │  │ SSH key   │  │ (never leaves)│ │  key mgmt only │             ▼                     │
 │  └───────────┘  └───────────────┘ │                │        SFTP server ◀── DB (users, │
 │   sshfs ──────────────────────────┼──── SFTP ─────▶│        quota, keys)    keys, quota│
 │     │ ciphertext dir (/mnt/c)     │  one port,     │             │                     │
 │     ▼ gocryptfs (client side)     │  SSH key auth  │        /srv/cryptstorage/<acct>/data   │
 │   ~/cryptstorage (plaintext)      │                │        (ciphertext only)          │
 └───────────────────────────────────┘                └──────────────────────────────┘
```

### 4.1 What happens to each server component

The table started as a proposal; it now records what was done (checked against `main` on 2026-10-30).

| Component | Before (server-side encryption) | Now (`main`) |
|---|---|---|
| `cryptdaemon/` | root daemon: mounted gocryptfs, ran Docker | **kept, much smaller, no longer root** (runs as the system account `cryptstorage`, also the SFTPGo container's user): only creates, re-keys and deletes SFTPGo users and their directories under `/srv/cryptstorage` and reports usage (`e2ee_provision`, `e2ee_set_key`, `e2ee_delete`, `e2ee_usage`); reached by the API over a socket with `DAEMON_AUTH_KEY`. No key ever passes through it |
| `sshcontainer/`, `docker_manager.py`, per-user ports and network | one container per mounted user | **removed**; one SFTPGo service, one port. Docker Compose still runs `webui`, `api`, `sftpgo`, `db` |
| `api/crypto.py` master-key wrapping, `mount_token.py`, session key, `recovery.py` | held and unwrapped keys | **removed**; wrapping and recovery run in the client (`cryptclient/e2ee/`) |
| `users.encrypted_master_key` | wrapped master key | **dropped** (no migration, section 15) |
| `users.recovery_encrypted_master_key` | master key wrapped with the recovery code | **kept under the old name**, now holds the recovery verifier (a slow hash of `HKDF(master key, "secdisk/recover-auth/v1")`) |
| `/storage/mount`, `/umount`, `/status`, `/auth/recover`, `/users/me/recovery-code` | server-side mount and recovery | **removed**; replaced by `/server-info`, `/storage/e2ee` (volume info, SSH host keys over pinned TLS), `/users/me/recovery-verifier`, `/auth/recover-e2ee` |
| API: accounts, Argon2id login, tokens, throttling, audit, e-mail | | **kept**; the login secret is the client-derived `AuthKey` (section 5a), never the password |
| Second factor (not in the original plan) | optional TOTP | **TOTP mandatory** (`REQUIRED_FACTORS`); **passkeys** (`webauthn_credentials`, `/auth/passkey/*`, CLI via browser login) |
| Stick secrets | | **new**: `stick_secrets`, one random secret per stick, encrypted under a key from `TOTP_ENCRYPTION_KEY`, released only after the full login (`/users/me/sticks`). A lost stick is locked at once (`stick_locks`, any session, the web UI included), unlocked only by the app's full sign-in, and removed for good only after `change_delay_hours` |
| Web sessions | | **new**: a sign-in in the web UI (passkey alone, or a one-time ticket from `cryptclient web-login`, `/auth/web/*`) gets a session that manages the account but is refused the stick secrets, the storage address, key and password changes and the escrow (`auth.get_full_user`); sensitive actions there accept a sign-in from the last 10 minutes instead of the password |
| Delayed changes | | **new**: `pending_changes`; SSH key change, account deletion and the removal of a stick wait `change_delay_hours` (default 24) and can be cancelled |
| Sync lock (design-features §5.1) | | **new**: `sync_locks`, `/storage/sync-lock`, one synchronisation per volume at a time |
| Escrow | | **new**: `users.escrow_blob` (sealed for the operator's offline key), `escrow_seals` (per-user consent), hash-chained `config_log` checked at API start, `/users/me/escrow` |
| API: SSH public keys | stored for the container | **kept**, provisioned into SFTPGo through the daemon |
| Quotas | optional XFS project quota | enforced by SFTPGo (per user, on write) |
| Backups | database **and** `/encrypted` | database, `/srv/cryptstorage` and SFTPGo's state with the SSH host keys ([BACKUP.md](BACKUP.md)). The database holds nothing that opens a volume, but it does hold the stick secrets: without it (or without `TOTP_ENCRYPTION_KEY`) every stick must be enrolled again; the data still opens with the password |
| fail2ban, nginx, TLS pinning, web UI shell | | **kept**; fail2ban covers SSH and the API, SFTPGo bans failed logins with its own defender |

### 4.2 SFTP front end: options

| | Description | For | Against |
|---|---|---|---|
| A | OpenSSH, per-user system accounts, `ChrootDirectory` + `internal-sftp` | nothing new to run; well-known | one OS account per user (needs a privileged provisioner); no quota except filesystem quotas; keys via `AuthorizedKeysCommand` |
| B | A small SFTP server written for CryptStorage (Go, `pkg/sftp`) | exactly what we need; no extra service | new security-critical code (path traversal, quota accounting, resource limits) that we would have to write and keep reviewing |
| C | **SFTPGo**, configured through its REST API | virtual users, public-key auth, per-user quotas, REST API and external-auth hooks (checked in its documentation) | another service to operate; licensed AGPL-3.0 |

**Decision: C, SFTPGo (see section 14, decision 1; first built as A, switched 2026-10-25).** The original recommendation was **C.** It removes the need to write a file server, and the API only has to create users,
register keys and set quotas through its REST API. AGPL-3.0 obliges you only if you *modify* SFTPGo
and offer it to others; running it unmodified as a separate service does not change the licence of
CryptStorage (AGPL-3.0-only since 2026-10-25, the same licence). Verify this reading with the SFTPGo licence text, and check whether
any feature CryptStorage would rely on is limited to a paid edition, before committing to it. If that
turns out badly, B is the fallback and A the minimal option.

## 5. Secrets

> **Superseded** by section 5a (decision 2): one password, from which the client derives the login key and the
> volume passphrase. The SSH key on the stick is sealed under the password and a stick secret the server
> releases only after the full login (key format v3, [design-stick-pin.md](design-stick-pin.md)).

| Secret | Held by | Purpose |
|---|---|---|
| Account password | the server stores an Argon2id verifier | web UI, key management, account recovery by e-mail |
| SSH private key | the user's USB stick, encrypted under the passphrase | authenticates to the SFTP service |
| **Encryption passphrase** | **only the user** | unlocks `gocryptfs.conf` and the USB key: one thing to type on the client |
| Master key | random, chosen by the client; stored only wrapped in `gocryptfs.conf` | encrypts the data |
| Recovery code | shown once to the user | the master key, with a checksum (section 6.5) |

**Two separate secrets (account password, passphrase) rather than one.** If one string did both jobs it
would be sent to the server at login. Keeping them apart means the server never receives anything
derived from the passphrase. (A single-password variant that derives an authentication key and an
encryption key from one secret is possible, as other products do; it is listed as an open question.)

**What the server can still attack.** It holds `gocryptfs.conf`, so a malicious server can try
passphrases offline against the scrypt-wrapped key. Mitigation: a strong passphrase and a higher
scrypt cost chosen at init (`-scryptn`; the client should pick a value that unlocks in roughly a second
on the user's machine, to be benchmarked). The USB key blob is a second offline target, which already uses Argon2id.

## 6. Flows

> **As built (2026-10-29).** `cryptclient setup` runs 6.1 in one conversation (account, e-mail confirmation,
> stick, storage, recovery code). `connect` **does** call the API: the login (password and second factor)
> releases the stick secret and returns the SFTP host keys over the pinned TLS connection, the escrow state
> and, with `--sync`, the sync lock. The "passphrase" is the account password (5a); `change-password`
> re-wraps `gocryptfs.conf`. A lost stick is locked under "USB sticks" in the web UI at once (its secret is
> no longer released; `connect` offers to unlock it after the full sign-in), and removing it for good deletes
> its secret. A new SSH key, account deletion and stick removal wait `change_delay_hours` (default 24 h)
> and can be cancelled.

### 6.1 First setup

1. **Account** (web UI): username, e-mail, account password. The server stores nothing else.
2. `cryptclient init-usb`: generates the SSH key pair, encrypts the private key under a new
   **passphrase**, writes it to the stick (as built: in its `.secdisk` folder).
3. `cryptclient register-key`: logs in with the account password and uploads the *public* key
   (the API provisions it into the SFTP service). Needs the e-mail-confirmed account.
4. `cryptclient init-storage`: generates a random 32-byte master key, runs
   `gocryptfs -init -masterkey=… ` against the (empty) remote directory with the passphrase, creates a
   canary file (below), prints the **recovery code once**.

### 6.2 Connect and disconnect

```
unlock USB key (passphrase) → in-memory ssh-agent → sshfs <server>:/ → /tmp/c      (ciphertext)
                            → gocryptfs -passfile … /tmp/c ~/cryptstorage          (plaintext)
disconnect: umount ~/cryptstorage → umount /tmp/c → close agent
```

No call to the API is needed: authentication is the SSH key. The server cannot learn the passphrase,
and there are no mount tokens.

### 6.3 Passphrase change

`gocryptfs -passwd` on the mounted ciphertext directory (it rewrites `gocryptfs.conf`, keeping a
`.bak`), then re-encrypt the USB key. The data is not re-encrypted.

### 6.4 Devices and lost sticks

Add a device: its public key is registered with the account password (and confirmed by e-mail, as
today). Lost stick: lock it in the web UI (immediate), remove it for good later (delayed). Whoever
holds the stick still needs the passphrase for the private key and for the data.

### 6.5 Recovery

The recovery code is the master key plus a short checksum, shown as grouped base32 (exact format to be
fixed in the prototype). Using it:

1. Check the checksum (catches typos before anything is written).
2. Mount the volume **read-only with `-masterkey`** on a temporary mount point and read the canary file
   (`.secdisk-canary`, created at the first mount; F6 shows gocryptfs cannot tell a wrong key by itself).
   If it does not read back, stop. The canary sits in the volume's root, where the user can see and delete
   it, so a deleted canary must not make a correct code useless (decided 2026-10-26): every unlock with
   the passphrase writes it again when it is missing, and when it is missing at recovery, any non-empty file
   that reads back proves the key (gocryptfs authenticates every block). A wrong key decrypts no names, so a
   volume that looks empty while its ciphertext directory has entries is refused (`e2ee.VerifyKey`).
3. Run `gocryptfs -passwd -masterkey=… ` with the new passphrase (F5), re-encrypt the USB key.
4. Mount with the new passphrase and read the canary again; if that fails, restore `gocryptfs.conf.bak`.
   Once it works, delete `gocryptfs.conf.bak`: it would let the old passphrase in. Password change deletes
   it after the server has the new login key, and every unlock deletes a leftover one.

The server takes no part, and a forgotten **account** password (e-mail reset) never affects the data.

### 6.6 Account deletion

The API deletes the user in the SFTP service together with the data directory.

## 7. API and web UI changes

> **As built:** no `/keys` endpoints; one SSH key per account (`PUT /users/me/ssh-key`, delayed). The new
> endpoints are `/server-info`, `/storage/e2ee`, `/storage/sync-lock`, `/users/me/sticks`, `/users/me/passkeys`,
> `/users/me/recovery-verifier`, `/auth/recover-e2ee` and `/users/me/escrow`; section 4.1 has the whole list.

- New or changed: `GET /storage` (SFTP host, port, quota and usage from the SFTP service);
  `POST /keys`, `GET /keys`, `DELETE /keys/{id}` (the password is required to add one; e-mail notice, as for the SSH key change today).
- Removed: mount, umount, status, recovery and master-key code paths (section 4.1).
- Web UI: account and key management, usage display. No mount button, no recovery card.
- Registration no longer produces a recovery code on the server.

## 8. Client changes

> **As built:** the commands are `setup`, `connect [--sync]`, `disconnect`, `status`, `tray`, `init-usb`,
> `upgrade-key`, `register`, `init-storage`, `change-password`, `recover`, `install-deps`, `diagnose` and
> `check-device`; no `migrate`. No pseudo-terminal is needed: the client writes `gocryptfs.conf` itself
> (12a). Windows uses cppcryptfs and SSHFS-Win (section 15).

| Command | Change |
|---|---|
| `init-usb` | unchanged layout and checks; the passphrase now doubles as the volume passphrase |
| `register-key` | new |
| `init-storage` | new: master key, `gocryptfs -init`, canary, recovery code |
| `connect` | no API login; sshfs of the ciphertext, then gocryptfs; unmounts in reverse order |
| `change-passphrase`, `recover` | new |
| `migrate` | new (section 9) |

- **Dependencies on the client:** `gocryptfs` and `sshfs` (plus macFUSE on macOS).
- **Master key on the command line.** `-masterkey=<hex>` is visible to other local users in the process
  list, and the manual recommends `-masterkey=stdin` instead. With a pty the passphrase also arrives on
  standard input, so whether both can be supplied that way is untested and part of spike S1.
- **Driving gocryptfs:** F3 means `init`/`-passwd` with a master key need a pseudo-terminal. A pty
  library works on Linux and macOS; **Windows has no equivalent and uses a different implementation
  (cppcryptfs)**, so Windows would start with documented manual steps. An alternative is to write
  `gocryptfs.conf` ourselves; its format is JSON with scrypt and AES-GCM, but implementing it is only
  sensible after reading gocryptfs's source and testing against it (spike S1).
- **Performance:** two FUSE layers (sshfs, gocryptfs) in series is slower than today's single
  gocryptfs on the server. To be measured (spike S3).

## 9. Migration of existing users

> **Not built** (decision 5): there were no users with data. Kept for the record.

Today's ciphertext directories are already valid gocryptfs volumes: `cryptdaemon` uses the **hex form
of the master key as the gocryptfs passphrase**. Two paths:

- **Quick:** the API returns that hex key once (after the account password), the client runs
  `gocryptfs -passwd` (old passphrase = the hex key, new = the user's passphrase), registers the SSH
  key, and the API then deletes the wrapped keys. Fast and keeps the data in place, but **the server
  has seen that master key**, and the files while mounted. The new guarantee holds for new data
  only if the master key is replaced.
- **Full:** the client creates a *new* volume with a new master key and copies the data across
  (read through the old volume, write to the new one), then the old one is deleted. This gives the
  guarantee for the existing data too, at the cost of transferring it.

Run a maintenance window, keep the old stack read-only until every user has migrated, then remove
the daemon, containers and wrapped-key columns. Rollback before that point: nothing was deleted yet.

## 10. Threat model: before and after

"Before" is the old server-side mode; "Now" is `main`, checked on 2026-10-30. [SECURITY.md](../SECURITY.md) has the full list.

| Adversary | Before | Now |
|---|---|---|
| Stolen disk, database dump or backup | protected | file contents and names protected; a **weak password** can be guessed offline against `gocryptfs.conf` and the login hash. Stick secrets in the database are encrypted under `TOTP_ENCRYPTION_KEY` (kept outside it) |
| Network attacker | TLS, pinning | client: TLS pinned on the stick, SSH host keys handed out over that connection; web UI: ordinary browser TLS and HSTS |
| Curious administrator | **sees keys and plaintext while mounted** | sees sizes, counts, timestamps, IPs. **With escrow** (`recovery_policy` `escrow` or `both`, and the user's consent) the operator can open the sealed recovery code and read everything (section 14) |
| Compromised running server | **keys and plaintext obtainable** | ciphertext and metadata only, **except** that it can serve altered web UI JavaScript and capture the password of anyone who types it there, which opens their data. The web UI does not need it (passkey alone, or `cryptclient web-login`), and a web session cannot reach the storage; the password form remains, labelled. The client and the tray are not affected |
| Other users of the service | isolated by containers | isolated by SFTPGo virtual users (public-key login only, own directory, quota, no shell or forwarding) |
| Stolen password | everything (with the old web mount) | needs the second factor (TOTP or passkey); with both, a new SSH key or an account deletion waits `change_delay_hours` (default 24) while the owner is told by e-mail and can cancel |
| Lost or copied USB stick | needs the password | needs the password **and** the full login: the stick secret is released only after password and second factor; no offline guessing; locked in the web UI at once, removed for good after the delay |
| Malicious server tampering | n/a (it is the trusted party) | **not prevented**: can rename or swap files, restore older versions, delete files (section 3) |
| Compromised client machine | exposed | exposed while the storage is open |
| Stolen laptop with a synchronised copy | n/a | the offline copy is plaintext; the client warns when disk encryption is off |

**Later work on integrity:** a client-held, signed manifest of the ciphertext tree with a version counter
kept on the stick would let the client detect swapped, rolled-back and deleted files. It is a feature of
its own and is not needed for G1.

**A forged volume.** A server cannot replace `gocryptfs.conf` with one of its own without the user's
passphrase failing to unlock it; the client reports a wrong passphrase and writes nothing. A *stale*
config (from before a passphrase change) behaves the same way.

## 11. Test plan

> **Status (2026-10-29):** the unit tests and the integration test (`scripts/e2ee_integration.sh`, also with
> the stick, setup and sync) exist and run in CI. The adversarial tests below run there too
> (`TestIntegrationTamper`, `TestIntegrationSyncTamper`; results in SECURITY.md). **Not done:** the double-FUSE
> benchmark (S3). Migration is dropped.

- Unit: recovery-code encoding and checksum, canary check, the pty driver against a fake gocryptfs,
  the `register-key` flow against a stub API.
- Integration in CI on a Linux runner with real gocryptfs and FUSE, and SFTPGo: init → write → connect
  twice → change passphrase → recovery with a **wrong** key refused before anything is overwritten →
  recovery with the right key → quota exceeded behaves as an ordinary write error → account deletion.
- Adversarial: swap two ciphertext files on the server, replace `gocryptfs.diriv`, restore an old
  `gocryptfs.conf`, truncate files; record what the client reports (the results go into SECURITY.md).
- Migration: a volume created by today's daemon is converted by both paths.

## 12. Plan

| Phase | Work | Size |
|---|---|---|
| 0 Spikes | S1 done (native config, 12a); Windows route done; S3 double-FUSE benchmark still open | small |
| 1 Server | SFTPGo service, key provisioning, new API endpoints (done; the flag went with phase 4) | medium |
| 2 Client | `init-storage`, `connect`, `change-password`, `recover`, `register` (done) | medium |
| 3 Migration | dropped (decision 5) | – |
| 4 Removal | delete containers, wrapped keys, old endpoints; update SECURITY.md and docs (done; the daemon stayed for SFTPGo users and runs unprivileged) | small |

## 13. Alternatives considered

- **Keep server-side encryption in a confidential-computing enclave (SEV-SNP/TDX).** Protects against
  an outside host, needs special hardware and remote attestation, does not remove the key from the
  server's own software.
- **Another format (Cryptomator, rclone crypt, restic).** Possible, but loses the existing volumes and
  gocryptfs's per-file layout; none is obviously better for an SSHFS-style mount.
- **CryFS.** Hides sizes and detects rollback (according to its documentation), but stores data in
  fixed-size blocks, which suits sync better than a remote mount and cannot read existing volumes.
- **A password-authenticated key exchange (e.g. OPAQUE) for login only.** Keeps the password from
  the server but leaves the master key and plaintext server-side; not a substitute for this change.

## 14. Decisions and open questions

**Decided 2026-10-24**

1. Server file service: ~~OpenSSH with `ChrootDirectory` and `internal-sftp` (option A in 4.2)~~ **superseded 2026-10-25: SFTPGo (option C)**. OpenSSH needed one OS account per user and a privileged provisioner, which made moving a server to another host awkward and left quotas to the file system. SFTPGo has virtual users, per-user quotas and a REST API, and the data directory plus its small database are all that moves. Cost: one more service and an AGPL-3.0 dependency (run unmodified, with attribution).
2. **One password.** The client derives two independent keys from it (section 5a). This replaces the two-secrets proposal in section 5.
3. Windows: **Linux first, Windows right after.** Linux is where the prototype is tested; the Windows route (cppcryptfs on Dokan, SSHFS-Win) is built and tested, see section 15.
4. The **server-side mount mode is removed**, together with the root daemon (the small daemon that remains runs as an unprivileged account, section 4.1). The web UI never shows files.
5. **No migration of existing data.** Only new installations use the new format; section 9 is not built. The old code path is deleted in phase 4.
6. Recovery: **both** the recovery code and an organisation (escrow) key can be offered; the operator chooses the policy at install time. Escrow decided 2026-10-26, see below.

**Escrow (decided 2026-10-26)**

Escrow lets the operator read everything, so the user must always know whether it applies to them. The protection must hold against everyone, the operator included. The operator controls the server and the web UI, so only the client (installed from the project's releases, not from the server) can really protect the user.

1. **The policy is locked at install.** `recovery_policy` and the escrow public key are chosen at install. A later change is an explicit operator action, not a quiet config edit.
2. **The state is per user.** A user is in escrow only if *their* master key was sealed (`PUT /users/me/escrow`). The API reports this per user, not the server setting.
3. **No seal without consent.** A user's key is never sealed unless the client has asked first and said that the operator can then read everything. Enabling escrow later, or a new escrow key, therefore needs every existing user's consent.
4. **The client detects changes (main protection).** At setup the client stores the policy and the escrow key fingerprint on the stick. On every connect it compares them with `/server-info`, warns loudly on any change, and never re-seals on its own.
5. **Status is shown** in the client (`status`, tray) and in the web UI: escrow on or off for this user, and the key fingerprint. The web UI copy is a convenience, because the operator can change it.
6. **Server audit log (secondary).** A hash-chained, append-only record of policy and escrow-key changes, checked when the API starts. A change between restarts is reported in the admin view and to the affected users by e-mail. This protects against other admins or an intruder, not against the operator.
7. **Turning escrow off does not end it.** A sealed copy may already have been kept. Escrow ends only with a new master key (rekey: re-encrypt all data). Even then, data the operator already copied, or holds in old backups, stays readable. The client must say this plainly.

**Still open**

- ~~Escrow design~~ decided 2026-10-26 (above). Rekey to really turn escrow off: planned (ROADMAP).
- ~~Web login with a derived key (5a): needs Argon2id in the browser.~~ Built (section 15). It still trusts the server that serves the page, so the web UI also signs in without the password: a passkey alone, or a ticket from `cryptclient web-login`, both giving a limited web session.
- ~~Recovery-code format and canary location~~ decided: the format is the one in `e2ee/recovery.go`;
  the canary stays at `.secdisk-canary` in the volume's root, with the fallback described in section 6.5.

## 5a. One password, two keys (decided design)

```
root       = Argon2id(password, salt = SHA-256("secdisk/kdf/v1" 0x00 lower(username)), t=3, m=64 MiB, p=4)
AuthKey    = HKDF-SHA256(root, info "secdisk/auth/v1")      -> sent to the server, which stores Argon2id(AuthKey)
VolumePass = HKDF-SHA256(root, info "secdisk/volume/v1")    -> hex text, the gocryptfs passphrase, never leaves the client
```

- The server gets only `AuthKey`. It cannot compute `VolumePass` from it (different HKDF labels, one-way).
- The salt needs no round trip, so login does not reveal whether a user exists.
- **The password must not be sent to the server at all**, otherwise the server could derive `VolumePass`. That includes the PHP web UI: it must derive `AuthKey` in the browser (JavaScript, Argon2id compiled to WebAssembly, served from our own origin with a pinned hash). If the web UI sent the password to PHP, the e2ee guarantee would end at the web server. This is the main usability and security cost of the single-password choice. It protects only against an honest server: the server also serves that JavaScript, so a malicious one can capture the password. The web UI has sign-ins that never put the password into the page (passkey alone, or a one-time ticket from the app); the password form stays, labelled as trusting the server.
- Changing the password changes both keys: the client re-wraps the master key (`gocryptfs.conf`) and updates the server verifier in one operation. The data is not re-encrypted.
- A weak password is a weakness against the server's offline guessing (it holds `gocryptfs.conf` and the verifier): the client must enforce a minimum length and show a strength hint.
- Reference test vector (any other implementation, such as the browser one, must match): username `alice`, password `correct horse battery` gives AuthKey `267d874c...69c4` and VolumePass `fe627d1d...9b4e` (full values in `cryptclient/e2ee/e2ee_test.go`, also reproduced independently in Python).

## 12a. Spike results (2026-10-24)

- **S1 passed, without a pseudo-terminal.** The client writes `gocryptfs.conf` itself (`cryptclient/e2ee/conf.go`). Verified against gocryptfs 2.4.0 in both directions: our code reads a config written by gocryptfs and recovers its master key; gocryptfs accepts our config (`-fsck`, and a mount with `-masterkey` reads back a file written through the passphrase mount) and rejects a wrong passphrase. This removes F3 as a blocker and also works on Windows, where there is no pty. The format is gocryptfs's undocumented-but-stable 2.x layout, so the real-gocryptfs test must stay in CI.
- The scrypt cost in a config read from the server is limited (2^10 to 2^22) so a hostile server cannot make the client allocate gigabytes.
- S2 (SFTPGo) was dropped by decision 1 and taken into use later (see decision 1). S3 (double-FUSE benchmark) is still to do.

## References

- gocryptfs manual (`-init`, `-passwd`, `-masterkey`): <https://github.com/rfjakob/gocryptfs/blob/master/Documentation/MANPAGE.md>
- gocryptfs threat model: <https://nuetzlich.net/gocryptfs/threat_model/>
- gocryptfs security audit (2017): <https://defuse.ca/audits/gocryptfs.htm>
- gocryptfs README (macOS, Windows/cppcryptfs): <https://github.com/rfjakob/gocryptfs>
- SFTPGo: <https://github.com/drakkan/sftpgo>
- CryFS, "How CryFS works": <https://www.cryfs.org/howitworks>

## 15. Implementation status (2026-10-30)

The old server-side mode has been **removed**; end-to-end is the only mode. There was no migration between the modes (decision 5).

**Built and tested**

| Part | Where | Verified by |
|---|---|---|
| Key derivation (one password, two keys), recovery code, native `gocryptfs.conf`, escrow seal | `cryptclient/e2ee/` | unit tests incl. a config written by real gocryptfs 2.4.0, and real gocryptfs accepting ours |
| Flows: connect, init, unlock, passphrase change, recovery | `cryptclient/volume/` | `scripts/e2ee_integration.sh` with real API, SFTPGo, sshfs, gocryptfs |
| Commands `register`, `init-storage`, `connect`, `change-password`, `recover` | `cryptclient/e2ee_cmds.go` | compiles for Linux, Windows, macOS; run through the same flows in the integration test (the commands themselves only add prompts) |
| API: login key as password, `/server-info`, `/storage/e2ee`, escrow, recovery verifier and `/auth/recover-e2ee`; the old mount/recovery endpoints no longer exist | `api/main.py` | `tests/test_e2ee_server.py` |
| SFTPGo user management (user, key, quota, delete) behind the daemon socket; no key ever passes through it | `cryptdaemon/sftpgo_client.py`, the `sftpgo` service in the compose file, `scripts/install_sftpgo.sh` | `tests/test_sftpgo_client.py` against a real SFTPGo 2.7.6: idempotent provisioning, key replace, delete, quota refusal, no shell, no port forwarding, no password login |
| Browser derives the login key (Argon2id in WebAssembly, hash-wasm 4.12.0, vendored); PHP refuses anything that is not a derived key | `webui/assets/`, `webui/auth.php` | `node webui/assets/derive.test.mjs` (same value as Go) and a real Chromium run: the password never appears in a request; with scripts off the page refuses before the API is called |
| Operator escrow tool | `scripts/escrow.py` | the integration test opens the user's sealed copy and compares the recovery code |
| Escrow visibility: consent before sealing, the accepted setting on the stick (`cryptstorage.escrow`) and a warning when the server's changes, per-user state in the web UI, hash-chained `config_log` checked at API start | `cryptclient/escrowcheck/`, `cryptclient/escrow_cmd.go`, `api/escrow_state.py`, `webui/dashboard.php` | `escrowcheck` and `volume` unit tests (no seal and nothing uploaded without consent), `tests/test_escrow_state.py` (change and tampering detected), `tests/test_webui.py`; the integration test agrees to the copy |
| Stick secret: key format v3, sealed under the password and a per-stick secret released after the full login; lock at once, remove after the delay | `api/sticks.py`, `cryptclient/usb/` | API tests, `usb` unit tests, the integration test with a stick image; real stick on Linux and Windows (2026-10-26/28) |
| One stick, one server: `server_id` in `/server-info` (HMAC of `TOTP_ENCRYPTION_KEY`), `cryptstorage.server` on the stick checked before the password, the key sealed only after an SFTP login with it worked | `api/sticks.py`, `cryptclient/stickserver/`, `cryptclient/stick_seal.go`, `cryptclient/setup/` | `stickserver` and `setup` unit tests (a stick of another server is left alone unless the user agrees), `tests/test_sticks.py`, the integration test checks the record |
| Second factor: TOTP mandatory, passkeys in the web UI and for the CLI via browser login | `api/totp.py`, `api/passkeys.py`, `webui/`, `cryptclient/browserlogin/` | API tests, `passkeys-browser` CI job; Android fingerprint and YubiKey by hand (2026-10-27) |
| Delayed SSH-key change, account deletion and stick removal with e-mail and cancel | `api/pending.py`, `webui/cancel.php` | API tests |
| Web UI without the password: passkey alone or a ticket from the app, limited web sessions | `api/main.py` (`/auth/web/*`), `api/auth.py`, `webui/index.php`, `cryptclient/weblogin_cmd.go` | `tests/test_web_session.py`, `passkeys-browser` CI job |
| Sync safety: local trash for 30 days, unreadable files named and left out, automatic recovery of an interrupted run | `cryptclient/syncer/` | `syncer` unit and integration tests, `TestIntegrationSyncTamper` |
| Tamper tests: what the client sees when the server changes the ciphertext | `cryptclient/volume/tamper_integration_test.go`, `cryptclient/syncer/tamper_integration_test.go` | CI; results in SECURITY.md |
| Build version everywhere | `scripts/version.sh`, `api/version.py`, `cryptclient/version.go` | `tests/test_version.py`, `version_test.go` |
| Sync (`connect --sync`): rclone bisync between `~/CryptStorage` and the volume, one sync per volume via a server lock | `cryptclient/syncer/`, `/storage/sync-lock` | `syncer` integration test; by hand on Windows with a real stick (2026-10-28) |
| Disk-encryption warning for the offline copy | `cryptclient/diskenc/` | unit tests |
| Unprivileged daemon: cryptdaemon and the SFTPGo container run as the system account `cryptstorage` | `ansible/roles/cryptdaemon/` | `sftpgo-container` CI job |

What the integration test proves: the server's files contain neither the plaintext nor the file name; a wrong password,
a wrong recovery proof and a wrong master key are all refused (the last one before anything is written); after recovery the data
is intact under the new password and the old one no longer works.

**How recovery works with one password.** A forgotten password cannot be reset by the server (it never had the volume key).
At `init-storage` the client uploads `HKDF(master key, "secdisk/recover-auth/v1")`; the server stores only a slow hash of it. With
the recovery code the client proves possession, the server sets a new login key, and the client re-wraps `gocryptfs.conf` itself
(after reading the canary file with the recovered key, which gocryptfs cannot check on its own).

**Recovery policy (`recovery_policy`)**: `user` (the user gets a code, nobody else can recover), `escrow` (no code for the user; the
operator opens the sealed copy with `scripts/escrow.py` and gives the code to the user), `both`. Escrow lets the operator read
everything: the client asks before sealing and warns when the setting changes (section 14, "Escrow").

**Known gaps (not done)**

- **Windows (tested in CI on a real Windows runner):** the encrypted volume is opened with **cppcryptfs 1.4 on top of the Dokan 2 driver** (not WinFsp; WinFsp is still needed for SSHFS-Win). Verified: cppcryptfs reads the `gocryptfs.conf` this client writes; gocryptfs on Linux decrypts files cppcryptfs wrote; the Windows job (`windows.yml`) runs mount, canary, wrong-passphrase detection and a read-only master-key mount (`e2ee/cppcryptfs_windows_test.go`). Known limits: cppcryptfs takes the volume passphrase on the command line of `cppcryptfsctl` for the moment of mounting (the derived passphrase, not the user's password; other processes of the same user could read it); the mount target is an empty directory or drive letter; the components are installed by `cryptclient install-deps` (pinned versions and SHA-256 in `cryptclient/deps/deps.go`, downloaded from the official release pages; also run by `cryptclient setup` and by the Inno Setup installer `packaging/windows/cryptstorage.iss`; the `installer` CI job proves this on a clean runner; the installer is not code-signed yet). **Connection (tested in CI, job `connection`):** SSHFS-Win mounts the server's `/data` as a drive (`sshconn/mount_windows_drive.go`: `sshfs.exe -f`, a key file deleted after the drive is up, SSHFS-Win's own `ssh` first in PATH because Windows' OpenSSH cannot use sshfs's pipe), the volume is created on it and unlocked by cppcryptfs, a file is written and the server holds only encrypted names. The server is a real Linux sshd in WSL; the test runs as an **ordinary user**. Known limit (the client refuses to run like this): **started from an elevated administrator token, SSHFS-Win cannot write** (the server answers the chown Windows asks for with permission denied) - the client should be run normally, not 'as administrator'. The full chain (`TestIntegration`, `TestIntegrationFullSetup`) also passes on a real Windows 11 machine against the real test server (own-runner workflow). The interactive `cryptclient setup` with a real stick passed by hand on Windows 11 (2026-10-28).
- **macOS:** the client compiles, but the route (macFUSE) is untested.
- **One stick at a time.** The account has one SSH public key (`users.ssh_public_key`), and every prepared stick gets a key pair of its own, so a second stick (a spare) replaces the first one's key after `change_delay_hours`. Since 2026-10-30 one stick works on Linux and Windows alike (below); sticks prepared on Linux by older versions keep their raw-sector key and work on Linux only until prepared again.
- **Setup:** `cryptclient setup` now walks through account, e-mail confirmation, stick, storage and the recovery code in one repeatable conversation (package `setup`, tested against the real server with a scripted user). It is a terminal program. Windows has an Inno Setup installer and the tray (`CryptStorage.exe`), both unsigned; the graphical setup wizard ([design-setup-app.md](design-setup-app.md)) is still to do. Windows: see [windows-testing.md](windows-testing.md).
- **Quotas are enforced by SFTPGo** (per user, on write). Its counter is its own; rescan after restoring from backup.
- **Legacy code is gone** (mounter, containers, wrapped-key columns; no data migration, as the project has no users with data). The column `recovery_encrypted_master_key` keeps its old name but holds the recovery verifier, and the daemon actions keep the `e2ee_` prefix.
- **Tray and udev autostart (Linux)** use the same connect flow as `cryptclient connect`, with zenity dialogs. The udev rule gives the seat's user access to the cryptkey stick only and starts a systemd user service; verified on an Ubuntu desktop with a real stick (2026-10-26: password dialog on insert, mount, disconnect). **Windows:** `CryptStorage.exe` (the same program built without a console) is the tray: a padlock next to the clock, a password window when the stick is plugged in, connect, disconnect and open from the menu, and start at sign-in (Win32 without cgo, `cryptclient/wingui`); tested by hand 2026-10-27. **Linux tray icon** (2026-10-30): `cryptclient tray` stays running with a padlock in the panel (StatusNotifierItem + dbusmenu over D-Bus, package `sni`, no cgo) and the same menu and connect logic as Windows (`tray_app.go`, shared); start at sign-in via XDG autostart. Tested against a private D-Bus with a scripted tray area, not yet by hand on a desktop. macOS: `cryptclient tray` falls back to the terminal. `cryptclient disconnect` from a second terminal only unmounts the plaintext layer.
- **A malicious server can delete or roll back files** and see sizes and timing (a gocryptfs property, section 3). A weak password can be guessed offline against `gocryptfs.conf`; the apps enforce 12 characters but not strength.
- TOTP on the account protects the server login only; it does not protect the data against someone holding a copy of the server's files.
- The `e2ee` job in `.github/workflows/ci.yml` and the Windows jobs run in CI; the Linux test server is deployed and checked by the `Deploy test server` workflow.

**USB stick on Windows and Linux.** Opening a physical drive needs administrator rights on Windows, and SSHFS-Win does not work with them, so the encrypted key blob and the serial binding are files in the hidden folder `.secdisk` on the stick's own file system instead of raw sectors (`usb/stickfiles.go`). Since 2026-10-30 Linux uses the same folder (no `sudo`, udev access rule or repartitioning), so one stick works on both; each OS family keeps its own serial binding (`serial.bin`, `serial-linux.bin`) because they read serial numbers differently, and a stick bound only on the other one is bound at its first use. Sticks prepared on Linux before keep their raw-sector key and work on Linux only until prepared again, which clears the raw sectors. They are still bound to the stick's serial number (a copy on another stick is refused). The stick needs no repartitioning there. Only USB disks are listed, never the system disk. Tested on a real stick through the own-runner workflow (`TestRealStickOnWindows`). The file is copyable, but since key format v3 the key in it is sealed with the stick secret the server releases only after the full login, so a copy cannot be attacked offline. The interactive `cryptclient setup` on Windows with a real stick passed by hand (2026-10-28).
