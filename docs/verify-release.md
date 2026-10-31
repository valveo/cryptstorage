# Verifying a release download

Every release has a `SHA256SUMS` file and its signature `SHA256SUMS.sigstore.json`. The signature is made
by the project's GitHub Actions release workflow with [sigstore/cosign](https://docs.sigstore.dev/) in
"keyless" mode: there is no long-lived private key to steal. The signing certificate names the exact
workflow and tag that built the files, and the signature is recorded in the public Rekor transparency log.
Checking it is free and takes a few minutes.

In the commands below, replace `0.1.0` / `v0.1.0` with the release you downloaded. The tag is part of the
signer's identity, so it must match the release exactly.

## 0. Download into one folder

From the [release page](https://github.com/valveo/cryptstorage/releases), download into the same folder:

- the file you want to install (for example `CryptStorageSetup-0.1.0.exe` or `cryptclient_0.1.0_amd64.deb`),
- `SHA256SUMS`,
- `SHA256SUMS.sigstore.json`.

`SHA256SUMS` lists every file of the release; you only need the ones for your system.

## 1. Get cosign

cosign is a single program from the sigstore project, downloaded from
[github.com/sigstore/cosign/releases](https://github.com/sigstore/cosign/releases). It is not installed and
needs no account.

Linux (amd64; use `cosign-linux-arm64` on ARM):

```
curl -L -o cosign https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
chmod +x cosign
```

macOS: `brew install cosign`.

Windows (PowerShell, in the download folder):

```
curl.exe -L -o cosign.exe https://github.com/sigstore/cosign/releases/latest/download/cosign-windows-amd64.exe
```

The cosign program itself is not code-signed for Windows either, so SmartScreen or an antivirus may warn about
it too.

## 2. Check the signature of SHA256SUMS

Linux and macOS:

```
./cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/valveo/cryptstorage/.github/workflows/release.yml@refs/tags/v0.1.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```

(Use `cosign` instead of `./cosign` if it came from a package manager.)

Windows (PowerShell, one line):

```
.\cosign.exe verify-blob --bundle SHA256SUMS.sigstore.json --certificate-identity "https://github.com/valveo/cryptstorage/.github/workflows/release.yml@refs/tags/v0.1.0" --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
```

It must print `Verified OK`. Anything else means: do not install.

## 3. Check the file you downloaded

Linux and macOS:

```
sha256sum --ignore-missing -c SHA256SUMS
```

It must print `OK` for your file (macOS without `sha256sum`: `shasum -a 256 --ignore-missing -c SHA256SUMS`).

Windows (PowerShell); prints `True` when the file matches:

```
$f = "CryptStorageSetup-0.1.0.exe"; (Get-FileHash .\$f).Hash.ToLower() -eq ((Select-String -SimpleMatch "  $f" .\SHA256SUMS).Line -split '\s+')[0]
```

## Windows SmartScreen

The Windows installer is not code-signed yet (a certificate costs money; a free signing programme for
open-source projects is being applied for). Windows may therefore show "Windows protected your PC".
After checking the file as above, click **More info → Run anyway**.

## Note for maintainers

The certificate identity contains the repository path. If the project ever moves to another repository,
update the commands above to the new path; releases made in the old repository keep verifying with the old one.
