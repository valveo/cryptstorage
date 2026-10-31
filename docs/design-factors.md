# Design proposal: authentication factors without extra hardware

Status: **tier 1 implemented** (TOTP, phase 1, and the `REQUIRED_FACTORS` server setting, phase 2, on by
default), together with the delayed key replacement, and **passkeys** (phase 5). Tier 2
(device-bound keys) is a proposal; tier 3 is the existing stick, sealed with a server-held secret. Written 2026-10-24.
Related: [design-e2ee.md](design-e2ee.md) (goal G6), [design-stick-pin.md](design-stick-pin.md),
[design-features.md](design-features.md).

## 1. Why

Goal G6 required access "only through the client and the USB stick". The intent behind it is that a
password alone must never be enough. The stick is a poor way to express that:

- An ordinary USB stick holds a copyable file, so it is only a weak "something you have". A hardware
  key such as a YubiKey is strong because the secret cannot leave the device, but it costs money, and
  the project wants to avoid costs for the companies that would run it.
- Phones and browsers cannot use the stick, which blocks the mobile and browser features.

The rule to keep is the classic one: at least two factors from different categories, something you know,
something you have, something you are.

## 2. Proposed wording for G6

> Every access requires at least two different factors (something you know, something you have,
> something you are). A USB stick is one allowed "have" factor, not the only one. The server operator
> chooses which combinations are accepted.

## 3. Factors that cost nothing

| Factor | Category | What it is | Portable |
|---|---|---|---|
| Password | know | Existing account password | yes |
| PIN, hardware rate-limited | know | Windows Hello PIN in the TPM, similar on other platforms | per device |
| Device-bound key | have | Key kept in TPM (Windows), Secure Enclave (macOS, iOS), Keystore (Android); cannot be exported | no, one per device |
| Phone one-time code (TOTP) | have | Authenticator app on the user's phone | yes |
| Passkey (WebAuthn) | have | Platform or phone passkey; resists phishing | per device or synced |
| Biometrics | are | Fingerprint or face, used only to unlock a local key; never sent to the server | per device |
| USB stick | have | Existing design; its key is sealed with a server-held secret (design-stick-pin.md, done without a PIN) | yes |
| Hardware security key | have | FIDO2 key for users who want the strongest option | yes |

Biometrics are not secret and the server cannot verify them. They only unlock a key held in secure hardware
on the user's own device.

## 4. Tiers

1. **Tier 1: password and TOTP.** Fast to build, works for the client, mobile and browser. Closes the
   "password alone gives full access" hole for online attacks.
2. **Tier 2: password or PIN and a device-bound key.** The SSH key lives in the platform's secure
   hardware. Strong and free, tied to the device.
3. **Tier 3: optional portable token.** USB stick or FIDO2 key for people who use many or shared computers.

## 5. What a second factor does not do

Authentication factors gate access through the server. They do **not** protect against an attacker who
holds a copy of the database: the master key is wrapped with the password, so a dump can be attacked
offline whatever factors are configured. That risk is addressed by the server-held secret in
design-stick-pin.md and by wrapping keys with a secret kept outside the database, not by TOTP or device keys.

## 6. Impact on the current project

Findings come from reading the code as it was on 2026-10-24, before the server-side mode was removed
(`api/main.py` login, `api/models.py`, the client's `sshconn/agent.go`, the daemon's container start-up).
Mount tokens and per-user containers no longer exist; see the notes in 6.1 and 6.2.

### 6.1 TOTP (tier 1)

| Aspect | Assessment |
|---|---|
| Benefit | Cheap, no hardware, works on every client; fixes online password-only compromise; reusable for the browser policy |
| Where it fits | `/auth/login` currently returns tokens and the mount token after the password check. It becomes a two-step flow: password, then code; the mount token is issued only after the code |
| Database | New columns or a table for the encrypted TOTP secret, enabled flag, last used time step (replay protection) and backup codes; migration 006 |
| Code | `api/main.py` login and recovery, `api/schemas.py`, `api/throttle.py` (separate failure counter for codes), `api/audit.py` (new events), `webui/index.php` (code field), `cryptclient` login prompts |
| Tests | New tests for enrolment, wrong and reused codes, throttling, backup codes, clock drift; existing 130 tests need the login helper updated |
| Drawbacks | Phishable in real time; users must keep the phone; needs a recovery path (backup codes, administrator reset) |
| Effort | Medium |
| **As built** | Done: two-step login, encrypted secret, replay protection, backup codes, an e-mail code for enrolment, step-up for risky actions; `REQUIRED_FACTORS=password,totp` by default. There are no mount tokens any more |

### 6.2 Device-bound keys (tier 2)

| Aspect | Assessment |
|---|---|
| Benefit | Non-exportable key, free, strong "have"; with Hello or Touch ID also "know" or "are"; rate limiting is done by the hardware |
| Where it fits | The client already isolates the key in its own agent (`sshconn/agent.go`). A custom agent whose signing calls the TPM or Secure Enclave replaces the in-memory key. The keys are ECDSA P-256, a type these chips support |
| Database | The `users` table holds a single `ssh_public_key`. Several devices need a separate devices table and revocation. (Containers are gone: SFTPGo users can hold several public keys, but the API and the daemon pass one.) Overlaps the device-credential work |
| Windows risk | Windows writes the key to a temporary file for the time of the mount because `sshfs-win` cannot use the in-memory agent (deleted once the drive is up). A non-exportable key cannot be written to a file, so this needs a spike to find out whether `sshfs-win` can use a named-pipe agent. If it cannot, tier 2 on Windows is blocked |
| Build impact | macOS Secure Enclave and Keychain need cgo, but the client is built with `CGO_ENABLED=0` for cross-compiling from Linux. The macOS build would have to run on macOS (signing and notarisation need that anyway). Windows can use the system crypto API without cgo |
| Drawbacks | One enrolment per device, which needs an invitation or QR flow; three platform implementations; TPM presence is not guaranteed on all Windows 10 PCs |
| Effort | Large |

### 6.3 USB stick and FIDO2 key (tier 3)

| Aspect | Assessment |
|---|---|
| Benefit | Portable across computers; already implemented; hardware keys are the strongest option |
| Drawbacks | An ordinary stick is copyable, but the copy is useless without the secret the server releases after the full login; a graphical setup is still missing |
| Effort | Already built; the stick secret done; setup app planned |

### 6.4 Operator policy: which factors are required

| Aspect | Assessment |
|---|---|
| Benefit | Lets a company choose its own balance (for example password plus TOTP, or password plus device key) |
| Reality check | The data model has no administrator role and no organisations. A first version can be a server setting (`REQUIRED_FACTORS`) instead of per-organisation policy |
| Code | Config validation at start-up, login logic that checks the satisfied factors, audit of policy changes |
| Drawbacks | Several accepted combinations multiply the cases to test; a misconfiguration can lock everyone out |
| Effort | Small for a server setting, large for real organisations |

### 6.5 Overall

- Doing tier 1 first gives the biggest security gain for the least change and does not touch the encryption
  design, the daemon or the containers.
- Tier 2 changes the client agent, the key model (one key becomes many) and the build, so it should follow
  the device-credential work.
- The existing stick keeps working throughout and becomes one factor among several.
- The wording change of G6 affects only documents, not code.

## 7. Plan

| Phase | Work |
|---|---|
| 0 | Spikes: `sshfs-win` with a named-pipe agent, TPM signing from Go on Windows, Secure Enclave signing on macOS |
| 1 | TOTP: enrolment, login, backup codes, throttling, tests (done) |
| 2 | `REQUIRED_FACTORS` server setting and enforcement for the web UI and the client (done) |
| 3 | Devices table, multiple SSH keys, revocation; enrolment flow shared with the device credentials |
| 4 | Device-bound key agent per platform |
| 5 | Passkeys in the web UI as the recommended second factor, TOTP kept as the required fallback (done 2026-10-26; since 2026-10-27 the web sign-in asks for the passkey first and offers the code as the fallback; tested with an Android phone and a FIDO2 key, not with an iPhone or a phone through a QR code); passkey login for `cryptclient` through the browser (webui/passkey-approve.php and a 127.0.0.1 listener, done 2026-10-26); FIDO2 as an encryption factor later |

## 8. Open questions

1. Is TOTP acceptable as the default second factor for the target companies?
2. Which platforms must have device-bound keys in the first version?
3. Do we need organisations and administrators, or is a server-wide setting enough? (For now: a server-wide setting.)
4. How are lost phones and devices handled (administrator reset, backup codes)? (Backup codes are built; there is no administrator reset.)
5. ~~Should a second factor also be required for the recovery code flow?~~ Yes, built: `/auth/recover-e2ee` checks it ("the recovery code replaces the password, not the second factor").
