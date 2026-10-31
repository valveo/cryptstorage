# Why CryptStorage

Status: **draft** for the v0.1 announcement (release checklist 4.1). To be reviewed by the maintainer. The
project is published as **Venomia CryptStorage** (decided 2026-10-27); this page is renamed with the move to
the public repository.

## The problem

Most organisations in Europe keep their files with a few large cloud providers under non-EU jurisdiction.
The provider can read the files, and so can anyone who can compel or compromise the provider. Self-hosting
moves the files to your own server, but then the people who run that server can read everything, and a
stolen server or backup gives everything away.

## What CryptStorage does

- **End-to-end encrypted.** Files are encrypted on the user's own computer before they leave it. The server
  stores only ciphertext and never sees a key or a password. (The web UI signs in with a passkey alone or
  through the app, without the password; the password form there still trusts the server.) A stolen server, disk or backup gives away
  file sizes and timing, not contents.
- **Self-hosted, open source.** You run the server yourself, on your own hardware or with a hosting
  provider you choose. AGPL-3.0, no licence fees, no account with us.
- **Feels like a normal drive.** After login the encrypted volume appears as a folder (Linux) or a drive
  letter (Windows). No special app for opening files.
- **Strong login.** Password plus a second factor (a passkey: fingerprint, face or security key; or an
  authenticator app code), a 24-hour delay with e-mail notice before sensitive changes take effect, and a
  USB key stick that holds the user's SSH key, sealed with a secret the server releases only after the full
  login, so a lost or copied stick is useless on its own.
- **Synchronised folder.** A local copy that works offline and stays in step with the server, with conflict
  copies instead of lost changes.
- **Proven building blocks.** [gocryptfs](https://nuetzlich.net/gocryptfs/) (cppcryptfs on Windows) for the
  encryption, [SFTPGo](https://github.com/drakkan/sftpgo) for storage, Ansible for the install.

## How it compares

| | Where the data lives | Who can read it | Self-hosted |
|---|---|---|---|
| **CryptStorage** | your server | only the users | yes |
| Nextcloud | your server | the server admin, unless end-to-end encryption is set up per folder | yes |
| Cryptomator | any cloud drive | only the user | the vault is; the cloud is not |
| Proton Drive, Tresorit | the provider's servers (Switzerland) | only the users | no |

The comparison is simplified. Nextcloud does far more than storage (calendar, office, chat), and Cryptomator
is an excellent choice for one person who already uses a cloud drive. CryptStorage aims at organisations that want
their own server **and** end-to-end encryption by default, with central user management.

## Who it is for

- **Companies and communities in the EU** that want an alternative to US cloud
  storage under their own control.
- **Administrators** who want a small, auditable stack: one API, one storage service, one client.
- **Individuals** comfortable running a small server.

## What it is not (yet)

- **Not audited.** It is a pre-release. Do not use it for the only copy of data you cannot lose.
- No shared folders yet (planned for v0.2, [design](design-sharing.md)), no phone app, no browser file access.
- macOS is untested. Windows binaries are not code-signed yet.
- See [SECURITY.md](../SECURITY.md) for what the design does not protect against (a malicious server can delete
  or roll back files, and it sees sizes and timing).

## What we are looking for

- **Testers** who install the server and the client and report what was unclear.
- **Pilot organisations** (5–20 people) willing to try it for real, alongside their current storage.
- **Security reviewers.** Read [docs/design-e2ee.md](design-e2ee.md) and tell us what is wrong.

Open an issue with the "Pilot or tester interest" template, or report vulnerabilities privately (SECURITY.md).
