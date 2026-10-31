# Release checklist: first public version (v0.1)

Status: **proposal**, written 2026-10-26, updated 2026-10-31. The goal is a first public version that is announced openly (for
example on LinkedIn) as a **pre-release looking for testers and pilot organisations**, not as a finished
product. Every item is free unless marked **(paid)**.

Target users: individuals, companies and communities in the EU that want self-hosted, end-to-end encrypted
storage instead of services under non-EU jurisdiction.

Name: the first public version is published as **Venomia CryptStorage** (domain venomia.fi, decided
2026-10-27). The renaming is done in the new public repository.

## 1. Must be done before the repository goes public

| # | Item | Why | Status |
|---|---|---|---|
| 1.1 | Scan the whole git history for secrets (`gitleaks detect` or GitHub secret scanning) | Making the repo public publishes every old commit, not just `main` | done 2026-10-26: only test fixtures found (allow-listed in `.gitleaks.toml`); CI job `secrets` scans every push |
| 1.2 | Check that test-server addresses, e-mail addresses and names in history and workflows are fine to publish | Same reason | done 2026-10-31: the security contact is security@venomia.fi; the test server's addresses moved out of the workflows into the repository variables `TEST_SERVER_HOST` and `TEST_API_URL`; the public repository starts without the old history |
| 1.3 | Enable private vulnerability reporting (Settings → Code security) | SECURITY.md already points to it | open |
| 1.4 | Confirm the response times in SECURITY.md ("maintainer to confirm") | A promise people will read | done 2026-10-30: 7 / 30 / 90 days, best effort |
| 1.5 | README states plainly: pre-release, not audited, do not use for data you cannot lose | Honest expectations protect the project's reputation | done |

## 2. Must work before the announcement

| # | Item | Why | Status |
|---|---|---|---|
| 2.1 | A server installs from the README on a clean host, including SFTPGo and a backup restore | The first thing an interested administrator tries | done 2026-10-31: clean-host fixes for Ubuntu 26.04 and Debian, demo.venomia.fi installed with Ansible, restore tested end to end including the TLS key in `/etc/letsencrypt` |
| 2.2 | HTTPS with Let's Encrypt and working SMTP on the deployed server | Registration, TOTP enrolment and the 24 h change delay rely on e-mail | done 2026-10-31: demo.venomia.fi on Matti's VPS with Let's Encrypt; mail through OVH (STARTTLS or implicit TLS on port 465); the test server uses a DuckDNS name |
| 2.3 | Linux client: `.deb` installs, `setup`, stick, connect, tray | Verified 2026-10-26 on Ubuntu | done |
| 2.4 | Windows client: the installer and `cryptclient setup` with a real stick | Most users in organisations have Windows; the parts are tested, the whole flow is not | done 2026-10-28: the installer, `cryptclient setup` with a real stick, connect with sync both ways and stick removal tested by hand on Windows 11 (F-Secure quarantined the unpacked binaries, the installed version works) |
| 2.5 | Someone other than the author follows the install guide from start to finish | The author cannot see the gaps in their own guide | skipped for v0.1 (Matti, 2026-10-31): the announcement asks for testers instead |
| 2.6 | A known-good demo: short screen recording or screenshots of setup and connect | People share and understand a video faster than a README | skipped for v0.1 (Matti, 2026-10-31): the announcement asks for testers instead |
| 2.8 | The web UI must not need the password typed into a page the server serves | A malicious server could capture it and read the data; this is the main promise | done: passkey alone or `cryptclient web-login`, web sessions limited; password form labelled |
| 2.9 | Stick lock, web sign-in from the desktop and the unreadable-file handling by hand on real devices, plus the Windows tray "Set up CryptStorage..." and setup asking the code once | Built and tested in CI, not by hand | open |
| 2.10 | One stick for both Linux and Windows | Testers with two computers will hit it | done 2026-10-31: the same ADATA stick works on Linux (VirtualBox VM) and Windows, by hand against demo.venomia.fi. Seen on the way: a stick moved out of the VM right after setup without ejecting came back with an empty key.bin. A spare stick (several SSH keys per account) is still open |
| 2.11 | Linux tray icon (padlock in the panel) on Ubuntu GNOME and one other desktop (KDE or Xfce) | Built 2026-10-30, tested against a scripted tray area only | open |
| 2.12 | A stick bound to its server: the tray set to another server refuses the stick before the password, `setup` against another server asks before preparing it, a URL change keeps working | The demo stick was once sealed to the old test server by a stale tray | built 2026-10-31, unit and integration tests; needs a hand test on Windows with the demo and the LAN test server |
| 2.7 | Passkeys on real devices | The recommended second factor | done 2026-10-27: Android fingerprint in the web UI, FIDO2 key on Windows in the web UI and the client. Not tried: iPhone, phone through a QR code (Bluetooth); say so in the release notes |

## 3. Release mechanics (free)

| # | Item | Notes |
|---|---|---|
| 3.1 | Version number and a `v0.1.0` tag; CHANGELOG | Done 2026-10-31: tag `v0.1.0` in the public repository; CHANGELOG and SECURITY.md "Supported versions" |
| 3.2 | A release workflow that builds the Linux `.deb`, the Windows installer and the static binaries from the tag | Done: `.github/workflows/release.yml` makes a **draft** pre-release from a `v*` tag; run it by hand for a dry run |
| 3.3 | `SHA256SUMS` and keyless signatures with sigstore/cosign from GitHub Actions | Done in the release workflow; how to verify: [verify-release.md](verify-release.md) |
| 3.4 | Apply to SignPath Foundation for Windows Authenticode signing | Free for OSI-licensed public projects. Until then document SmartScreen's "More info → Run anyway" |
| 3.5 | Decide macOS: leave it out of v0.1 and say so | Signing and notarisation need Apple Developer **(paid, 99 USD per year)**. README and CHANGELOG say macOS is not supported in v0.1 |

## 4. Announcement

| # | Item | Notes |
|---|---|---|
| 4.1 | One-page "why CryptStorage" (draft: [why-cryptstorage.md](why-cryptstorage.md)): the problem, how it differs from Nextcloud, Cryptomator, Proton Drive and Tresorit, who it is for | The first question every reader will have |
| 4.2 | Clear ask: testers, pilot organisations (5–20 people), security reviewers | Turns attention into feedback |
| 4.3 | Roadmap visible: shared folders ([design-sharing.md](design-sharing.md)), setup app | Done: [ROADMAP.md](../ROADMAP.md) release plan (v0.1 personal storage, v0.2 shared folders, decided 2026-10-26) |
| 4.4 | Issue templates for bugs and pilot interest | Done: `.github/ISSUE_TEMPLATE/` (security reports go to the private form) |

## 5. Soon after (not blocking v0.1)

- **Independent security review.** The NLnet Foundation's NGI Zero programme (EU funding for open-source
  projects that strengthen digital sovereignty) also arranges free security audits for the projects it
  funds. Apply once the repository is public. Check the current call and its conditions first.
- Passkeys on an iPhone and through a phone's QR code (needs testers with those devices).
- Done before v0.1 after all: the server-held stick secret (without a PIN) and the Windows tray.

## Open questions

1. ~~Is the announcement aimed mainly at organisations, individuals, or both equally?~~ Companies and
   communities in the EU first (2026-10-26).
2. ~~Is there a public demo server, or only self-hosting?~~ Both: demo.venomia.fi runs on Matti's VPS
   **(paid, about 4–7 € per month)** since 2026-10-30, with a 3-hour account lifetime
   (`demo_account_lifetime_hours`). A demo server carries data-protection obligations for other people's
   data: the demo notice on its pages says not to store anything real.
3. Who besides the author can test the install guide before the announcement?
