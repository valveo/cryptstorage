# Upgrading a server

Before 1.0 any release may change the database, the storage format or the API. The
[changelog](../CHANGELOG.md) says for each version what changes and whether anything must be done by
hand. Read the entries of every version between yours and the new one before you start.

## Order

**Server first, then the apps.** A newer app works against the server version it was released with, and
an older app keeps working against a newer server unless the changelog says otherwise.

## A server installed with install.sh

```
sudo cryptstorage-update --check     # which version runs here, which is the newest
sudo cryptstorage-update             # back up, then install the newest
```

`cryptstorage-update` never runs by itself; you start it when the moment suits. It then

1. downloads the release's server package and checks it against the signed `SHA256SUMS`
   ([verify-release.md](verify-release.md)). **It needs `cosign` for that** and stops without it;
   `--no-signature-check` goes on regardless, trusting the download address alone;
2. checks that the server can run the new version;
3. takes a backup into `/var/backups/cryptstorage` (`--backup-dir` for another place);
4. installs the new version with the saved settings and waits until the server reports it.

Nothing is changed before step 4, and it stops at the first step that fails.

**What the backup holds.** By default everything an upgrade changes: the database, the SFTPGo state,
the settings and the keys (`cryptstorage-backup --without-files`). That takes seconds and a few
megabytes, and it is enough to undo the upgrade. It does **not** hold the users' encrypted files,
which an upgrade does not rewrite. With

```
sudo cryptstorage-update --full
```

the backup is complete, files included. That needs as much free space as the users have stored
(ciphertext does not compress) and correspondingly long; the command checks the space first. Either
way, the copy lies on the same disk: it protects against a failed upgrade, not against a lost
server, and does not replace your regular backups ([BACKUP.md](BACKUP.md)). The backups are not
removed automatically; delete old ones when the new version has proved itself.

A server without internet access: bring `cryptstorage-server-X.Y.Z.tar.gz`, `SHA256SUMS` and
`SHA256SUMS.sigstore.json` into a directory and run `sudo cryptstorage-update --from /that/directory`.

Then continue from step 5 below (check the result, update the apps). Releases before 0.1.3 have no
server package; a server running one of them is brought to 0.1.3 with the steps below or, when it
already has its settings on the server, by running the new version's `sudo ./install.sh`.

## A server installed from another machine

1. **Take a backup and copy it off the server** ([BACKUP.md](BACKUP.md)):
   ```
   sudo cryptstorage-backup /srv/backups
   ```
   This backup is the only way back: there are no down-migrations (see "Going back").
2. On the machine you deploy from, get the new version (a release tag, not `main`) and check it
   ([verify-release.md](verify-release.md)):
   ```
   git fetch --tags && git checkout v0.1.2
   ```
3. Deploy it with the same inventory as before:
   ```
   cd ansible
   ./setup-files.sh
   ansible-playbook -i inventory/my-hosts.yml site.yml
   ```
   The playbook rebuilds the containers and restarts them. Connected users lose the connection for a
   moment; the apps reconnect, a running synchronisation is repeated.
4. **The database is brought up to date when the API starts.** New tables are created, and the numbered
   files in `api/migrations/` that the database has not had yet are applied in order and recorded in the
   table `schema_version` (`api/migrate.py`). Nothing to run by hand.
5. Check the result:
   ```
   curl -s https://<domain>/api/health            # "version" is the new one
   sudo cryptstorage-admin users                  # the accounts are there
   ```
   Then sign in with one account and open its storage.
6. Update the apps on the users' computers. If the release fixes a security problem in the app, tell
   the users, and once they have updated set `min_client_version` in the inventory (for example
   `0.1.2`) and run the playbook again: apps older than that then ask for an update instead of opening
   the storage. Apps older than 0.1.2 do not know this setting and are not stopped by it.

## If the API does not start after an upgrade

`docker compose -f /opt/cryptstorage/docker-compose.yml logs api` shows why. Two messages come from the
database check:

- **"Database migration NNN_... failed"**: a schema change could not be applied. The files before it
  stay applied and the API does not start with a half-upgraded database. Fix the cause named in the
  message (for example a full disk) and restart the API; it continues from the file that failed.
- **"The database is at schema version N, but this server only knows up to M"**: the database was
  already used by a newer version than the one now deployed. Deploy the newer version again, or go back
  as below.

## Going back

An older server version must not run on a database that a newer one has changed, and refuses to. To
return to the old version, deploy it and restore the backup from step 1 (BACKUP.md, "Restoring").
Whatever users stored after that backup is then gone from the server, so decide quickly after an
upgrade whether it stays.

After `cryptstorage-update` the backup is the directory it printed, and the old version is still
unpacked in `/var/lib/cryptstorage/releases/<old version>` (or wherever you first ran `install.sh`):

```
cd /opt/cryptstorage && sudo docker compose down
sudo tar -C /opt/cryptstorage -xzf <backup>/sftpgo.tar.gz
sudo tar -C /etc -xzf <backup>/cryptdaemon-etc.tar.gz
sudo docker compose up -d db
gunzip -c <backup>/db.sql.gz | sudo docker compose exec -T db sh -c 'exec mariadb -uroot -p"$MYSQL_ROOT_PASSWORD" cryptdb'
sudo /var/lib/cryptstorage/releases/<old version>/install.sh --upgrade
```

A backup made without `--full` puts back accounts and settings as they were; the files in the
storage directory stay as they are now. An account created after the backup is gone, and its files
remain on the disk without an owner until you remove them.
