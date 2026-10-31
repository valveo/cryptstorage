# Verifying a release download

Every release has a `SHA256SUMS` file and its signature `SHA256SUMS.sigstore.json`. The signature is made
by the project's GitHub Actions release workflow with [sigstore/cosign](https://docs.sigstore.dev/) in
"keyless" mode: there is no long-lived private key to steal. The signing certificate names the exact
workflow and tag that built the files, and the signature is recorded in the public Rekor transparency log.
Checking it is free and takes a minute.

## 1. Check the signature of SHA256SUMS

Install cosign (a single binary, see the cosign documentation), download `SHA256SUMS` and
`SHA256SUMS.sigstore.json` from the release page, and run (replace `v0.1.0` with the release you downloaded):

```
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/valveo/cryptstorage/.github/workflows/release.yml@refs/tags/v0.1.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```

It must print `Verified OK`. Anything else means: do not install.

## 2. Check the file you downloaded

Linux and macOS, in the download folder:

```
sha256sum --ignore-missing -c SHA256SUMS
```

Windows (PowerShell): compare the output of `Get-FileHash .\CryptStorageSetup-0.1.0.exe` with the line for
that file in `SHA256SUMS`.

## Windows SmartScreen

The Windows installer is not code-signed yet (a certificate costs money; a free signing programme for
open-source projects is being applied for). Windows may therefore show "Windows protected your PC".
After checking the file as above, click **More info → Run anyway**.

## Note for maintainers

The certificate identity contains the repository path. When the project moves to a new public repository
, update the command above to the new path; releases made in the old repository keep verifying with
the old one.
