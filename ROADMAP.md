# Roadmap

Nothing beyond the current release is promised. The roadmap after v0.1 is planned openly in this
repository's issues once the first version is out; the items below are the direction, not commitments.

**Name.** The project is **Venomia CryptStorage** (short: CryptStorage; domain venomia.fi), formerly
secdisk. Some internal names keep the old name on purpose, because changing them would break existing keys,
sticks or volumes: the key derivation labels (`secdisk/kdf/v1` and the others), the stick's `.secdisk` folder
and the `.secdisk-*` files in a volume.

## v0.1: personal encrypted storage (first public pre-release)

One user, one volume, Linux and Windows clients. See the [CHANGELOG](CHANGELOG.md) for the full list. In short:

- End-to-end encryption on the user's machine (gocryptfs format); the server stores only ciphertext.
- A USB key stick whose key is sealed with a secret the server releases only after the full sign-in, so a
  lost stick cannot be attacked offline; a lost stick is locked in the web UI at once. The same stick works
  on Linux and Windows and belongs to one server.
- Mandatory two-factor sign-in: authenticator app, and passkeys in the web UI and in the client.
- A web UI that does not need the password (passkey, or a one-time sign-in from the app).
- A synchronised local folder with a server-side lock, conflict copies, a 30-day local trash and a warning
  when the folder's disk is not encrypted.
- Optional operator escrow, off by default, visible to every user and never applied without consent.
- Windows tray and installer, Linux tray and `.deb`, server install with Ansible.

Known untested for v0.1: passkeys on an iPhone and passkeys through a phone's QR code (Bluetooth); macOS is
not supported (signing and notarisation would need a paid Apple developer account, 99 USD a year).

## v0.2: shared folders for groups and organisations

End-to-end encrypted shared folders with roles and member removal, and invite-only registration for
organisation servers. Design: [docs/design-sharing.md](docs/design-sharing.md).

## Later (proposals)

- A setup app that prepares the stick in one guided step ([docs/design-setup-app.md](docs/design-setup-app.md)).
- Device credentials and an HTTP file gateway; browser access as an organisation policy; a mobile app
  ([docs/design-features.md](docs/design-features.md)).
- Device-bound keys in TPM, Secure Enclave and Keystore ([docs/design-factors.md](docs/design-factors.md)).
- A FIDO2 key as a real encryption factor (hmac-secret / PRF).
- Rekeying a volume (a new master key), needed to really turn escrow off for a user.
- Performance measurements of the double FUSE layer and of sync over a real internet connection.
- Windows code signing through a free programme for open-source projects.
- macOS (paid signing, see above).

## Design documents

- [docs/design-e2ee.md](docs/design-e2ee.md): client-side encryption, threat model, what is verified and the
  known gaps (section 15).
- [docs/design-stick-pin.md](docs/design-stick-pin.md): the server-held secret for the stick.
- [docs/design-factors.md](docs/design-factors.md): authentication factors without extra hardware.
- [docs/design-features.md](docs/design-features.md): sharing, sync, offline use, mobile and browser access.
- [docs/release-checklist.md](docs/release-checklist.md): what had to be done before the first public version.
