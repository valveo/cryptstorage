# Testing the client on Windows

Status 2026-10-29: the whole Windows route is tested on real Windows (see docs/design-e2ee.md, section 15); the
tray `CryptStorage.exe` and the installer with `cryptclient setup`, a real stick and sync were tested by hand (2026-10-27/28). This page says how to repeat the tests and how to try the client by hand.

## What is tested automatically

| Where | What | How to run |
|---|---|---|
| GitHub-hosted Windows runner (`.github/workflows/windows.yml`) | build, unit tests, `diagnose`; opening a gocryptfs volume with cppcryptfs and Dokan; the installer on a clean machine; the SSHFS-Win connection to a real Linux sshd (WSL) as an ordinary user; the synchronised folder with two devices (rclone, `TestSFTPSync`) | by hand from the Actions page (Windows minutes count double against the free quota) |
| Own Windows machine as a self-hosted runner (`.github/workflows/windows-selfhosted.yml`, label `self-hosted, windows`) | the whole chain against the real test server, the real USB stick, the warning for "run as administrator" | every pull request that touches `cryptclient/` (unit tests and the full chain incl. the synchronised folder, against the LAN test server in the repository variable `TEST_API_URL`); by hand from the Actions page, where inputs `usb_probe`, `usb_test`, `elevated_only` choose a part (all `false` = full chain) |

A pull request run stops leftover `cppcryptfs` and `sshfs` processes on the runner machine first, so a
session opened there by hand is closed. Runs never come from a fork's pull request (the job checks the
head repository); look at this again before the repository is public.

The runner account must be an **ordinary user** (not an administrator) for the full chain and the stick test; the
administrator warning is tried with an administrator account. A fresh Windows client refuses `.ps1` files; the
workflow lifts that for the job with `PSExecutionPolicyPreference`.

## Trying the client by hand

Windows 10 or 11, a virtual machine is fine (VirtualBox, Hyper-V, VMware). Windows 7 and 8 are not supported. A USB stick
needs USB passthrough to the VM.

1. Install with `CryptStorageSetup.exe` (artifact of the `installer` job), or copy `cryptclient.exe` and run
   `cryptclient install-deps` (downloads Dokan, WinFsp, SSHFS-Win and cppcryptfs; pinned versions and SHA-256 in
   `cryptclient/deps/deps.go`; `deps-hashes.yml` prints new values when a pin is updated). The installer puts
   cppcryptfs and rclone next to the client in `Program Files\CryptStorage`; a loose `cryptclient.exe` keeps them in
   `%LOCALAPPDATA%\cryptstorage`, where antivirus heuristics such as F-Secure DeepGuard may quarantine them.
2. Run `cryptclient diagnose` (changes nothing) and, if something fails, paste its output into an issue.
3. Start `cryptclient setup` from a **normal** window. Do not use "Run as administrator": SSHFS-Win cannot write then, and
   the client stops with an explanation.

On Windows the encrypted key lives in the hidden folder `.secdisk` on the stick's drive, not in raw sectors (raw disk access
needs administrator rights). The stick needs no repartitioning. Linux uses the same folder, so a stick prepared on one works
on the other (bound to its serial number on each at its first use there).

## Test server on the LAN

A native end-to-end test server is installed on the Linux test machine by the `Deploy test server` workflow
(`scripts/deploy_testserver.sh`): the API in e2ee mode on port 8099 (plain HTTP, e-mail verification off, SQLite)
and SFTPGo (public-key SFTP) on port 2223, both as systemd units that start at boot. **Test use only**: no TLS,
the API runs as root, the escrow private key is on the machine (`/etc/cryptstorage/escrow.env`), and anyone who can
reach the ports can register an account.

```
cryptclient setup
```

Setup asks for the server address once (type the test server's address, e.g. `http://192.168.1.10:8099`; without a scheme `https://` is
assumed) and saves it in `%AppData%\cryptstorage\env`, so `connect` and the Start-menu shortcut find it later.
`set CRYPTSTORAGE_SERVER=...` still works and wins over the saved address.

The API tells the client to use the address in `SERVER_HOST` for SFTP; it is set when the workflow runs (input
`server_host`, default the LAN address; use the public name to reach it from outside, with ports 8099 and 2223
forwarded in the router).

### Web UI over HTTPS, for passkeys with a real phone

Passkeys need HTTPS and a real name. The workflow can add the web UI behind nginx with a Let's Encrypt
certificate on a free DuckDNS name (`scripts/testserver_https.sh`). No router port has to be opened:

1. On duckdns.org, add a second name for the test server, e.g. `mytest` (keep the name the SSH deploy used
   apart). Copy the account's token into the repository secret `DUCKDNS_TOKEN`.
2. Run `Deploy test server` by hand with `https_domain` = `mytest.duckdns.org`. The script points the name
   at the machine's LAN address and gets the certificate through the DNS challenge. Later runs keep the name.
3. On the phone (same Wi-Fi), open `https://mytest.duckdns.org/`, register, turn on the authenticator app,
   then add a passkey on the dashboard. Without SMTP the e-mail codes are in the API log:
   `sudo journalctl -u cryptstorage-api | grep -i code`.
4. Sign in on a computer and choose the passkey: the browser shows a QR code, and the phone approves (this needs
   Bluetooth on the computer). `cryptclient` signs in the same way through the browser.

Tested 2026-10-27: the passkey with an Android phone's fingerprint in the phone's own browser, and a FIDO2 key
(YubiKey) in the Windows VM, both in the web UI and in `cryptclient`. Not tried yet: an iPhone, and step 4
with a phone through the QR code.

If the name does not resolve on the LAN, the router blocks public names that point to private addresses
(DNS rebinding protection): allow the name in the router, or point it at the public address and forward port 443.
Passkeys are bound to the name: they stop working when the real domain replaces it.

## Still untried on Windows

- Done 2026-10-28: the installer and the interactive `cryptclient setup` with a real stick (ADATA 4 GB), connect with
  `--sync` both ways, and pulling the stick out disconnects cleanly.
- Done 2026-10-27: the tray `CryptStorage.exe` (padlock next to the clock, password window when the stick is plugged
  in, starts at sign-in; log `%LOCALAPPDATA%\cryptstorage\tray.log`), tested by hand on the Windows VM.
- The installer is not code-signed; SmartScreen warns.
