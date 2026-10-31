# Backup and restore

User data is only recoverable from **these things together**:

| What | Where | Why it matters |
|---|---|---|
| The database | MariaDB (`cryptdb`) | Accounts, login hashes, TOTP secrets and passkeys, recovery verifiers, escrow blobs and the escrow settings log, and the **stick secrets** (TOTP and stick secrets are encrypted under a key from `TOTP_ENCRYPTION_KEY`, which is not in the database: keep it too, apart from the backup). |
| The ciphertext | `/srv/cryptstorage` (`storage_dir`) | The users' encrypted files (gocryptfs format, one directory per user). |
| The SFTPGo state | `<install_dir>/sftpgo` | SFTPGo's user database and the **SSH host keys**. Without the host keys every client reports a changed server key. |
| The TLS certificate and key | `/etc/letsencrypt` | The clients **pin the server's public key** (saved on every stick). A restored server with a new key is refused by every client until each stick is set up again. |
| The daemon's settings | `/etc/cryptdaemon` | The SFTPGo admin password that the restored SFTPGo database expects (a new install generates another one, and the daemon could then no longer manage users), and the daemon's auth key. |

The ciphertext is unreadable without a user's password or recovery code, and the database holds no volume
key; still, treat all three as secrets. Neither the server nor the backup can open the files.

## Making a backup

```
sudo cryptstorage-backup /srv/backups
```

The playbook installs `scripts/backup.sh` as `/usr/local/sbin/cryptstorage-backup`. It writes `db.sql.gz`,
`storage.tar.gz`, `sftpgo.tar.gz`, `cryptdaemon-etc.tar.gz`, `letsencrypt.tar.gz` (when the server has
`/etc/letsencrypt`) and `SHA256SUMS` into a private (`0700`)
timestamped directory, and fails if the dump or an archive cannot be read back. Copy the directory
somewhere else (another machine, another site): a backup on the same disk is not one.

**Consistency.** Files change while users are connected, so a plain `tar` can capture a file in the
middle of a write. For a clean copy take the backup at a quiet time, snapshot the file system first
(LVM, ZFS, btrfs) and archive the snapshot, or run it twice and keep the second.

Test restoring regularly; an untested backup is a hope, not a backup.

## Restoring (also how to move to another server)

0. Point the domain at the new host, then put the TLS certificate back **before** the playbook runs:
   `tar -C /etc -xzf letsencrypt.tar.gz`. The playbook then keeps it (certbot only runs when no certificate
   exists) and the clients' pin still matches. If the playbook already made a new certificate, restore the
   archive over it and `systemctl reload nginx`.
1. Install the stack on the new host (Ansible) and stop it: `docker compose -f /opt/cryptstorage/docker-compose.yml down`
2. Put the data back: `tar -C /srv -xzf storage.tar.gz`, `tar -C /opt/cryptstorage -xzf sftpgo.tar.gz` and
   `tar -C /etc -xzf cryptdaemon-etc.tar.gz`
3. Start only the database: `docker compose -f ... up -d db`
4. Load the dump: `gunzip -c db.sql.gz | docker compose -f ... exec -T db sh -c 'exec mariadb -uroot -p"$MYSQL_ROOT_PASSWORD" cryptdb'`
5. **Run the Ansible playbook again** (the same inventory). This is not optional: the restored
   `/etc/cryptdaemon` holds the old daemon auth key, while the API container still has the one the first run
   wrote, and the API then fails every storage call (`/storage/e2ee` answers 500, "Unauthorized"). The second
   run gives the API the restored key, gives the files to the system account `cryptstorage` (`tar` keeps the
   old host's uid numbers) and starts everything.
6. Log in as a user and connect; the first connection of every user proves the set is consistent.

There are no system accounts to move: the users live in SFTPGo's database (and are recreated from the API's
data on the next connection if that is lost). Restore the database and the storage from the **same backup**: a
user created after the archive has no storage in it; storage deleted since then reappears.

On a server with `demo_account_lifetime_hours` set, the worker deletes every restored account older than that
right after the restore, as it should.

Tested end to end on 2026-10-31 (demo.venomia.fi reinstalled from scratch and restored): the TLS pin, the SFTP
host keys, the logins (password + TOTP) and the stored files all came back unchanged.

## Things that make a restore fail

- **A different database for the same ciphertext** (or the reverse). Keep them together.
- **Lost TLS key** (`letsencrypt.tar.gz` not restored): the new certificate has another key, and every
  client refuses the server because the pin on its stick no longer matches. Each user has to set the stick up
  again. Backups made before 2026-10-31 do not contain it.
- **Lost SSH host keys.** Restore `sftpgo.tar.gz`. Without it SFTPGo makes new keys; clients accept them only
  because the API lists the new public keys over the pinned TLS connection (older clients refuse them).
- **Lost stick secrets** (database without the `stick_secrets` rows, or a lost `TOTP_ENCRYPTION_KEY`): the key on
  every stick (format v3) can no longer be opened and each user has to enrol a new stick. A new
  `TOTP_ENCRYPTION_KEY` also gives the server a new `server_id`, so clients say that the server was set up again
  and `cryptclient setup` prepares the stick anew. Restoring the key keeps the id, also on a new machine
  with new SSH host keys. The data is not lost: it
  still opens with the password. A lost `TOTP_ENCRYPTION_KEY` also disables everyone's TOTP. Keep that key with the backup,
  but not in the same place.
- **Lost `JWT_SECRET_KEY` / `REFRESH_TOKEN_HMAC_KEY` / `DAEMON_AUTH_KEY`:** these do *not* protect data;
  restoring without them only logs everyone out. New ones can be generated (`ansible/generate-secrets.sh`).

## What a user needs to get back in

- Their password, **or**
- their **recovery code** (shown once at setup). Using it sets a new password and keeps the data.
- With recovery policy `escrow` or `both` the operator can also recover the code (`scripts/escrow.py`).

If a user loses the password and the recovery code and there is no escrow, the data cannot be read by anyone.
