# CryptDaemon

A small host-level Python daemon that manages the users of the [SFTPGo](https://github.com/drakkan/sftpgo) service holding users' **ciphertext**.
It listens for commands from the API container over a Unix socket. It never receives a key or a
password: files are encrypted on the client (see `docs/design-e2ee.md`).

## Architecture

```
[API container (FastAPI)]
        │  Unix socket (/run/cryptdaemon/cryptdaemon.sock), HMAC-SHA256 on every command
        ▼
[Host daemon (cryptdaemon)]
        │
        ▼
sftpgo_client: REST calls to SFTPGo (127.0.0.1:8081) + the user's data directory under storage_dir
```

## Files

```
cryptdaemon/
├── daemon.py            # Unix socket loop, peer credential check
├── handler.py           # Validates a command and runs it (one lock per user)
├── validator.py         # Strict command validation (fields, user_id, SSH key, quota)
├── socket_auth.py       # HMAC-SHA256 + nonce replay protection
├── sftpgo_client.py  # Creates/deletes SFTPGo users, sets keys and quotas, reads usage
├── cryptdaemon.service  # systemd unit
└── README.md
```

## Actions

| action | purpose |
|---|---|
| `e2ee_provision` | create the user (optionally with the SSH public key and quota); idempotent |
| `e2ee_set_key`   | replace the account's SSH public key |
| `e2ee_delete`    | delete the account and all its data |
| `e2ee_usage`     | bytes used by the account (and the free space against the quota) |

The `e2ee_` prefix is historical; it was kept so the protocol did not change when the old
server-side mode was removed.

## Security notes

- **Not root.** The daemon runs as the system account `cryptstorage` (a free system uid picked at install, or `storage_uid`), which owns the storage and is also the user of the SFTPGo container, with no capabilities (`CapabilityBoundingSet=`, `NoNewPrivileges`, `ProtectSystem=strict`; it writes only the storage directory, its socket and its log). Its config in `/etc/cryptdaemon` is `root:cryptstorage 0640`.
- Socket `0600` by default; with `CRYPTDAEMON_SOCKET_GID` it is `0660 cryptstorage:<gid>` (the daemon is a member of that group) so the API container can connect. The directory is mounted into the container, so the socket survives a daemon restart.
- Every command carries an HMAC (`DAEMON_AUTH_KEY`), a timestamp and a nonce; a replayed command is refused.
- The validator accepts only known fields; a key or password in a command is rejected.
- Commands for the same user are serialised; different users run in parallel.
- Quota: `quota_bytes` is set on the SFTPGo user, which refuses writes beyond it. A quota of 0 would mean unlimited in SFTPGo, so the daemon substitutes the 10 GiB default.
- SFTPGo's REST API is on the loopback; its admin password is read from `SFTPGO_ADMIN_PASSWORD_FILE`. Users cannot log in with a password, over FTP/WebDAV/HTTP, or get a shell.
