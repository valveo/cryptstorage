# Design proposal: server-assisted PIN for the USB key stick

Status: **server secret implemented 2026-10-26, without the PIN** (decided to do before v0.1). Written 2026-10-22.

**What was built** (`api/sticks.py`, `cryptclient/stickkey`, key format v3 in `cryptclient/crypto/sealed.go`):
the stick secret `S` of section 3, but released after the **full login** (password and second factor)
instead of after a PIN check. The key is `K = HKDF(Argon2id(password, salt) || S)`. Since the client
has encrypted end to end (design-e2ee.md), the password is checked by the login anyway, and the
second factor is mandatory, so the throttled login already is the online guess limit of section 4; a
PIN would add a third secret to remember. The real attack it closes was: copy the stick, guess the
password offline, then use the SSH key for SFTP, which needs no second factor, and decrypt the
downloaded ciphertext with the password. A lost stick is switched off by locking it (web UI, "USB
sticks"; immediate, unlocked only from the app) and removed for good by deleting its secret after the
change delay. `S` is stored encrypted (AES-GCM) under a key derived from `TOTP_ENCRYPTION_KEY`, which lives
outside the database (section 5's instance key); sticks with an older key format are sealed on their next connect. No PIN on top (decided by the maintainer 2026-10-26). The sections below are the
original proposal.
Related: [design-setup-app.md](design-setup-app.md), [design-e2ee.md](design-e2ee.md) (goal G6),
the earlier fixes: the password alone must not give access, and a key replacement waits with a cancel link.

## 1. Why

The stick holds the user's SSH private key in raw sectors as a 300-byte blob (ECDSA P-256 key, 227 bytes
as PEM, encrypted with Argon2id and AES-256-GCM). Anyone who has the stick can copy the blob and try
passwords on their own computer, without touching the server and without any limit on the number of
guesses. The only defence is the strength of the password, so a short numeric PIN would be unsafe
(a 6-digit PIN has 10^6 combinations; at roughly 0.1 to 0.5 s per Argon2id guess, which is an estimate and
not a measurement, a single computer tries them all in days, and a 4-digit PIN in minutes).

This system cannot be used without the server. That allows the guess limit to be enforced there, which
makes a short PIN acceptable.

## 2. Goals and non-goals

**Goals**

- P1. Someone holding only the stick cannot recover the private key offline, whatever the PIN.
- P2. Someone knowing only the account password cannot obtain the private key.
- P3. A short PIN (4 to 6 digits) is enough for the user; guesses are limited by the server.
- P4. No new cryptographic primitives: use HKDF, Argon2id and AES-256-GCM as today.

**Non-goals**

- Protection against malware on a computer where the key is in use (the key is in memory as today).
- Protection if the server is fully compromised. The server is already trusted while a user is logged in
  (see SECURITY.md); this design does not change that.
- Replacing the account password, which still protects the account and the master key.

## 3. Proposal

The server holds, per stick, a random 256-bit **stick secret** `S`. The key blob on the stick is encrypted
with a key derived from both the PIN and `S`:

```
K = HKDF( Argon2id(PIN, salt) || S )          # 256-bit
blob = AES-256-GCM( K, private key PEM )
```

Equivalent alternative: split the private scalar into two additive shares, one on the stick and one on the
server. The encrypted-blob form is simpler and reuses the existing format, so it is the proposal.

To connect, the client:

1. Reads the blob from the stick and asks the user for the PIN.
2. Sends the stick identifier and a PIN proof to the server over the pinned TLS connection.
3. The server checks the proof, counts the attempt, and returns `S` only on success.
4. The client derives `K`, decrypts the key into the in-process agent, then logs in and mounts as today.

The PIN proof must not let the server (or someone with a database dump) test PINs cheaply. It is derived
from the PIN with Argon2id and a per-stick salt, and the server stores only a keyed hash (HMAC) of it
with a server-side key that is not in the database.

## 4. Attempt limits and lockout

- At most 5 wrong proofs, then the stick is locked and the owner is e-mailed.
- Unlock needs the recovery path (recovery code or e-mail confirmation with a delay), because a thief
  could otherwise lock the real owner out on purpose.
- The counter is stored in the database, not in memory (SECURITY.md lists in-memory throttling as a
  weakness), and every attempt is audited.

## 5. Where `S` and the verifier live

- `S` is stored encrypted with an instance key kept outside the database (a protected file or hardware
  module). A database dump alone must not allow offline PIN guessing.
- `S` is part of the backup. Losing it makes that stick unusable; the user then enrols a new stick.
- Rotating the instance key re-encrypts all `S` values.

## 6. Threat model

| Attacker has | Outcome |
|---|---|
| Stick only | Cannot guess offline: `S` is missing. Online guesses are limited and visible |
| Account password only | No private key; cannot mount (needs the second factor and the key-replacement delay too) |
| Stick and password | Still needs the PIN, and guesses are limited by the server |
| Database dump | `S` and the verifier are protected by the instance key |
| Database dump and instance key (full server compromise) | PIN guessable offline; same trust level as today |
| Computer with the unlocked key in memory | Out of scope |

## 7. Alternatives

- **Strong passphrase, no server involvement.** Four or five random words give roughly 50 to 65 bits and
  need no server change. Simpler, and the fallback if this design is not built.
- **PIN-only offline protection.** Rejected: see section 1.
- **Hardware PIN (smart card, security key, TPM).** Rate-limits in hardware, but needs hardware the users
  do not have.
- **OPRF or OPAQUE-style protocol.** Lets the server help without learning the PIN. Stronger, relevant if
  the project moves to client-side encryption (design-e2ee.md), but clearly more complex.

## 8. Test plan

- Unit: key derivation and blob format, PIN proof, attempt counter, lockout and unlock.
- Integration: connect with the right PIN, wrong PIN five times (lock), unlock through recovery, backup
  and restore of `S`.
- Adversarial: stick copied without the server, replay of an old proof, database dump without the
  instance key, parallel guesses from many addresses.

## 9. Plan

| Phase | Work |
|---|---|
| 0 | Decide between this design and the passphrase fallback; short review of the key derivation |
| 1 | Server: `S` storage, proof check, attempt counter, lockout and unlock, audit |
| 2 | Blob format v3 and client flow; migration from v2 (re-encrypt with PIN and `S` at upgrade) |
| 3 | Setup app and wizard ask for the PIN; documentation |

## 10. Open questions

*Answered by what was built:* 1 no PIN, the account password; 2 the login's own throttling; 3 a key derived
from `TOTP_ENCRYPTION_KEY` (an environment secret, not in the database); 4 a lost stick is deleted, a new one
enrolled. Question 5 is still open.

1. PIN or passphrase as the default, and may users choose a longer secret instead of digits?
2. Number of attempts and lock duration.
3. Where the instance key lives (file with restricted rights, or a hardware module).
4. Should the unlock path be e-mail only, or also the recovery code?
5. Does an independent review of the derivation happen before release?
