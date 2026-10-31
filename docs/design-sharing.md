# Design proposal: end-to-end encrypted shared folders

Status: **proposal, not implemented.** Written 2026-10-26. Planned for **v0.2** (v0.1 is
personal storage only, decided 2026-10-26).
Related: [design-e2ee.md](design-e2ee.md) (key derivation 5a, recovery 6.5), [design-features.md](design-features.md)
section 4, [design-factors.md](design-factors.md).

Decision taken 2026-10-26: **shared folders stay end-to-end encrypted.** The server must not be able to
read a shared folder any more than a personal one. Server-side encryption for shared folders (the easier
option in design-features.md section 2) is not used.

## 1. Why

Today each user has one encrypted volume that only they can open. Companies and communities need folders
that several people use together, with members added and removed over time. Without shared folders
CryptStorage cannot replace a team drive, however good the encryption is.

## 2. Goals and non-goals

**Goals**

- SH1. A shared folder is encrypted on the members' machines; the server stores only ciphertext and
  never holds a key that opens it.
- SH2. Members have a role: **owner** (adds and removes members, deletes the folder), **write**, **read**.
- SH3. Adding a member needs no secret exchange outside CryptStorage and works while the new member is offline.
- SH4. Removing a member cuts their access at once, and the folder can be re-keyed so that a removed
  member's old key opens nothing written afterwards.
- SH5. The existing personal volume, key derivation, recovery code and stick keep working unchanged.
- SH6. Works on Linux and Windows with the tools already in use (gocryptfs, cppcryptfs, SSHFS).

**Non-goals**

- Links for people without an account (needs the HTTP gateway).
- Cryptographic read-only. Anyone holding a folder key could write valid ciphertext. **Read-only is
  enforced by the server** (SFTPGo permissions), which is honest to state: a malicious server could let a
  reader write, but it could also delete everything anyway (design-e2ee.md non-goals).
- Hiding membership from the server. The server knows who belongs to which folder.

## 3. The building blocks

### 3.1 One gocryptfs volume per shared folder

Each shared folder is its own gocryptfs volume in its own directory on the server, with its own random
master key, so removing one folder or one member never touches the others.

The volume's `gocryptfs.conf` wraps the master key under a **folder passphrase**: 32 random bytes chosen
by the owner's client, written as hex. Members never type it; their client unwraps it (3.3). Using a
passphrase rather than mounting with `-masterkey` means the same mount path as the personal volume works
with both gocryptfs and cppcryptfs.

### 3.2 A key pair for every user

To give a folder passphrase to someone without meeting them, each user needs a public key:

```
user key pair      = random X25519 key pair, created by the client at setup (or on first use)
public key         -> stored on the server, readable by other users of the same server
private key        -> stored on the server wrapped twice:
                        AEAD(HKDF(root, "secdisk/userkey/v1"), private)   (opened with the password)
                        AEAD(HKDF(master key, "secdisk/userkey-recover/v1"), private)   (opened with the recovery code)
```

- A random key pair (not one derived from the password) means a password change re-wraps one small blob
  instead of every folder key, and the recovery code restores sharing as well as the personal volume.
- With `recovery_policy=escrow` the operator can already open the personal master key, and so the user
  key and every shared folder of that user. The client must say so, as it does today.

### 3.3 Wrapping a folder passphrase for a member

```
wrapped = HPKE-Seal(member public key, info = "secdisk/share/v1" || folder id || member id, folder passphrase)
```

HPKE (RFC 9180, base mode, X25519 + HKDF-SHA256 + ChaCha20-Poly1305) is a standard, reviewed construction.
Binding the folder id and member id into `info` stops the server from moving a wrapped key to another
folder or another member. Only the wrapped value is stored on the server, one per member.

### 3.4 Can the member trust the public key? (the hard part)

The server hands out public keys. **A malicious server could give the owner its own key instead of the
new member's**, and then read everything the owner shares. This is the weak spot of every system of this
kind; Proton and Tresorit address it with key verification. Proposal:

1. Each user key has a short **fingerprint** (safety number) shown in the client and in the web UI.
2. When an owner adds a member, the client shows the member's fingerprint and asks to compare it with the
   member (in person, by phone, by chat). Optional, but recommended; skipping is recorded.
3. The client **pins** every member key it has seen. A changed key is refused until the user confirms the
   new fingerprint.

This keeps SH1 true against a server that turns malicious *after* keys were verified, and states plainly
that an unverified first contact trusts the server.

### 3.5 Server side: one SFTP view per user

SFTPGo **virtual folders** map a server directory into a user's SFTP tree with its own permissions and
quota. Each share becomes `/srv/cryptstorage/shares/<folder id>/` and appears to each member as
`/shares/<folder id>` with `list,download` for readers and full rights for writers. The personal volume
stays at `/data`. Removing a member removes the virtual folder from their SFTPGo user at once.

## 4. Flows

### 4.1 Create

1. The owner's client creates a random folder passphrase and a new gocryptfs volume in a fresh share
   directory (the API asks the daemon to create the directory and the SFTPGo folder).
2. It wraps the passphrase for the owner's own public key and stores the wrapped value.
3. A canary file is written, as for the personal volume.

### 4.2 Add a member

1. The owner picks an existing account on the same server and a role.
2. The client fetches the member's public key, shows the fingerprint (3.4), wraps the folder passphrase
   (3.3) and uploads the wrapped value. The API records the membership and the daemon maps the folder.
3. The member's client sees the new folder at the next connect and mounts it.

### 4.3 Connect

After the personal volume is up, the client lists the user's folders, unwraps each folder passphrase with
the user's private key and mounts each volume beside the personal one (4.6 for where).

### 4.4 Remove a member

- **Step 1, immediate (server):** the API deletes the membership and the wrapped key, and the daemon removes
  the virtual folder from that member's SFTPGo user. The member can no longer download anything.
- **Step 2, re-key (client of an owner):** a new volume with a new folder passphrase is created, the owner's
  client copies all files from the old volume into it, wraps the new passphrase for the remaining
  members, and the server swaps the directories and deletes the old one. gocryptfs cannot change the
  master key in place, so re-keying costs a full copy.
- Step 2 protects against a removed member who also gets hold of the server's files later (for example a
  leaked backup). The client offers it after every removal; the owner may postpone it for a large folder.
  Until it is done, the client shows the folder as "not re-keyed since <name> was removed".

### 4.5 Leaving, lost passwords, last owner

- A member may leave a folder; that is a removal without re-keying, which owners may then do.
- A member who loses their password and has no recovery code loses their user key; an owner simply adds
  their new key again.
- **If the only owner loses access, nobody can add members any more.** The client warns when a folder has
  one owner and suggests a second.

### 4.7 Organisation servers and public services

Sharing is meant for a server run by one organisation. A server setting `registration` decides the mode:

- `invite` (organisation server): accounts are created by invitation only; shared folders are available,
  and an **administrator** role can remove a departing member from all folders at once (step 1 of 4.4;
  re-keying is still done by an owner's client) and can **vouch for a user's key at invitation** (for
  example after checking it in person), so members need not compare fingerprints with each other.
- `open` (public service with self-registration): shared folders are off by default.

This is a default, not a guarantee: the code is open, and an operator can change the setting. It also does
not remove the key-trust problem in 3.4, because an organisation's own server can be broken into as well;
it only gives that check a natural owner.

### 4.6 Mount points

Linux: `~/cryptstorage` (personal) and `~/cryptstorage-shared/<folder name>/` per folder. Windows: one
drive letter per volume does not scale; mounting each folder into an empty directory is supported by
cppcryptfs (design-e2ee.md section 15) and is the proposal, to be confirmed in the spike.

## 5. Concurrent use

gocryptfs was built for one writer per volume. A shared folder has several machines writing into the same
ciphertext through SSHFS. gocryptfs has a `-sharedstorage` option for a backing directory used by several
instances at once.

### 5.1 Spike result (2026-10-26, Linux)

Setup: gocryptfs 2.4.0, sshfs 3.7.3 (`-o reconnect`, otherwise default caching), OpenSSH server on the same
host; two independent SSHFS mounts of one ciphertext directory, each with its own gocryptfs mount (two
"machines"). Run once without and once with `-sharedstorage`; afterwards the ciphertext was checked from a
fresh mount and with `gocryptfs -fsck`.

| Test | Without `-sharedstorage` | With `-sharedstorage` |
|---|---|---|
| A creates a file, B reads it | visible at once | visible at once |
| A creates a directory, both write files into it | OK | OK |
| A overwrites a file B had read, B reads again | new content at once | new content within about 1 s (one transient read error) |
| 100 + 100 files written in parallel, different files | all intact | all intact |
| A renames, B lists | OK | OK |
| 200-character file name (long-name files) | OK | OK |
| **Both overwrite the same file in place at the same moment** (20 rounds) | **file corrupted**: unreadable, authentication failure, `-fsck` reports it | **same** |
| Both write a temporary file and rename it over the same name (20 rounds) | not run | intact, last writer wins |
| B reads while A rewrites the file in place 60 times | not run | 1 of 60 reads failed, then fine |

Conclusions:

- **Different people on different files works**, including new directories, renames and long names.
- **Two machines writing the same file in place at the same time destroys that file**, not just one of the
  edits. `-sharedstorage` does not prevent it. This is worse than an ordinary network drive, where the
  last writer wins.
- **Writing to a temporary file and renaming it is safe** (last writer wins, file intact). Microsoft Office
  and LibreOffice save this way and also leave lock files the other user's application sees; simple
  editors and many scripts overwrite in place.
- Use `-sharedstorage` for shared folders anyway: it is what gocryptfs recommends for this case and costs
  little here.
- **Not tested yet:** cppcryptfs on Windows (it has no `-sharedstorage` equivalent that we know of), a real
  network with latency, and mixed Linux and Windows writers.

### 5.2 Consequences for the design

1. **Versions of the ciphertext on the server**, so a corrupted file can be restored. The server can keep
   them without any key (for example file-system snapshots or SFTPGo hooks copying the previous version),
   and the client can offer "restore previous version". This is needed before shared folders are offered.
2. **Lock hint in the client:** when a file in a shared folder is opened for writing, the client could
   place a small lock marker the other clients show ("Matti is editing"). It cannot stop an application
   that ignores it, so it is a hint, not a guarantee.
3. **The synchronised folder (built 2026-10-26: rclone bisync with a server-side lock per volume,
   design-features.md 5.1) suits shared folders better than a live mount:** each
   client edits a local copy and uploads whole files with temporary-file-and-rename, keeping a conflict
   copy when both sides changed a file. That turns the corruption case into a visible conflict.
4. Users are told plainly: two people must not edit the same file at the same time; Office files are
   protected by Office's own lock files.

## 6. Data model and API (outline)

| Table | Columns |
|---|---|
| `user_keys` | user id, public key, private key wrapped by password, private key wrapped by recovery, fingerprint, created |
| `shares` | id, name (encrypted by the client? see open question 3), created by, quota, last re-key |
| `share_members` | share id, user id, role, wrapped folder passphrase, added by, added at, fingerprint verified (yes/no) |

Endpoints: create share, list my shares, add member, change role, remove member, start and finish re-key,
get a user's public key. Every change is audited and e-mailed to the owners. Changes made by an owner
need the second factor (step-up, as for SSH key changes).

## 7. Threat model

| Attacker | Can they read a shared folder? |
|---|---|
| Server stores and backups only | No: ciphertext and wrapped keys only |
| Malicious server, keys verified | No; it can still delete, roll back, or refuse service |
| Malicious server, keys **not** verified when a member was added | **Yes, from then on**, by substituting its own key (3.4) |
| Removed member, before re-key | Only with a copy of the server's files; the server already refuses them |
| Removed member, after re-key | Only files they had already copied |
| Reader trying to write | The server refuses; cryptographically they could |

## 8. Plan

| Phase | Work |
|---|---|
| 0 | Spikes: two writers on one gocryptfs volume over SSHFS (Linux done 2026-10-26, section 5.1); the same with cppcryptfs on Windows; server-side versions of the ciphertext; cppcryptfs mounting several volumes into directories; SFTPGo virtual folders with per-user read-only permissions |
| 1 | User key pairs and fingerprints (client, API, recovery and password-change flows) |
| 2 | Server: tables, endpoints, daemon and SFTPGo virtual folders, audit and e-mail |
| 3 | Client: create, add, list, mount on connect; tray shows the shared folders |
| 4 | Remove and re-key |
| 5 | Review of the key handling before release |

## 9. Alternatives considered

- **Server-side encryption for shared folders.** Much simpler, but the server could read them. Rejected
  (decision above).
- **One key per file, as Proton Drive does.** Allows sharing single files and re-keying without a full
  copy, but means writing our own encrypted file format and dropping gocryptfs. Too large for now; can be
  revisited for the HTTP gateway.
- **Sharing the personal volume's passphrase.** Would give away the whole personal volume. Rejected.

## 10. Open questions

1. Is re-keying after removal offered (owner decides) or forced?
2. What exactly may the administrator of an `invite` server do (4.7)? Proposal: remove members and vouch for
   keys, but never read a folder (the administrator holds no folder key unless added as a member).
3. Should folder names be encrypted? The server then shows only ids, which makes support harder.
4. Is fingerprint verification optional with a warning, or required for adding a member?
5. Quota: does a shared folder use the owner's quota or its own?
