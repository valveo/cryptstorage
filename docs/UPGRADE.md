# Upgrading a server

Before 1.0 any release may change the database, the storage format or the API. The
[changelog](../CHANGELOG.md) says for each version what changes and whether anything must be done by
hand. Read the entries of every version between yours and the new one before you start.

## Order

**Server first, then the apps.** A newer app works against the server version it was released with, and
an older app keeps working against a newer server unless the changelog says otherwise.

## Steps

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
