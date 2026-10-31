#!/usr/bin/env bash
# Backs up everything that is needed to restore a CryptStorage installation's user data:
#
#   db.sql.gz          the database (accounts, login hashes, recovery verifiers, escrow blobs; guard it like a secret)
#   storage.tar.gz     the users' ciphertext under /srv/cryptstorage
#   sftpgo.tar.gz      the state of the SFTPGo service (its user database and, importantly, the SSH host
#                      keys: without them every client sees a changed server key)
#   cryptdaemon-etc.tar.gz  /etc/cryptdaemon: the SFTPGo admin password that matches the restored SFTPGo
#                      database, and the daemon's auth key (guard it like a secret)
#   letsencrypt.tar.gz /etc/letsencrypt: the TLS certificate and its PRIVATE KEY. The clients pin the public key
#                      (CRYPTSTORAGE_CERT_PIN on the stick): a new key locks every client out. Only when
#                      the directory exists (not on a plain-http test server).
#   SHA256SUMS
#
# All parts are needed for a full restore. The ciphertext alone is unreadable (the keys live with the users).
#
#   scripts/backup.sh /path/to/backups
#
# Environment: COMPOSE_FILE (default /opt/cryptstorage/docker-compose.yml), DB_SERVICE (db),
#              STORAGE_DIR (/srv/cryptstorage), SFTPGO_STATE_DIR (/opt/cryptstorage/sftpgo), ETC_DIR (/etc/cryptdaemon),
#              LE_DIR (/etc/letsencrypt)
# See docs/BACKUP.md, including how to get a consistent copy while users are mounted.
set -euo pipefail
umask 077

DEST="${1:?usage: backup.sh <destination-directory>}"
COMPOSE_FILE="${COMPOSE_FILE:-/opt/cryptstorage/docker-compose.yml}"
DB_SERVICE="${DB_SERVICE:-db}"
STORAGE_DIR="${STORAGE_DIR:-/srv/cryptstorage}"
SFTPGO_STATE_DIR="${SFTPGO_STATE_DIR:-/opt/cryptstorage/sftpgo}"
ETC_DIR="${ETC_DIR:-/etc/cryptdaemon}"
LE_DIR="${LE_DIR:-/etc/letsencrypt}"

OUT="$DEST/cryptstorage-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT"

echo "Dumping the database..."
docker compose -f "$COMPOSE_FILE" exec -T "$DB_SERVICE" \
  sh -c 'exec mariadb-dump --single-transaction --routines -uroot -p"$MYSQL_ROOT_PASSWORD" cryptdb' \
  </dev/null | gzip > "$OUT/db.sql.gz"

echo "Archiving $STORAGE_DIR, $SFTPGO_STATE_DIR and $ETC_DIR..."
tar -C "$(dirname "$STORAGE_DIR")" -czf "$OUT/storage.tar.gz" "$(basename "$STORAGE_DIR")"
tar -C "$(dirname "$SFTPGO_STATE_DIR")" -czf "$OUT/sftpgo.tar.gz" "$(basename "$SFTPGO_STATE_DIR")"
tar -C "$(dirname "$ETC_DIR")" -czf "$OUT/cryptdaemon-etc.tar.gz" "$(basename "$ETC_DIR")"
parts=(db.sql.gz storage.tar.gz sftpgo.tar.gz cryptdaemon-etc.tar.gz)
if [ -d "$LE_DIR" ]; then
  echo "Archiving $LE_DIR (TLS key: the clients' pin depends on it)..."
  tar -C "$(dirname "$LE_DIR")" -czf "$OUT/letsencrypt.tar.gz" "$(basename "$LE_DIR")"
  parts+=(letsencrypt.tar.gz)
fi

# A backup that cannot be read back is not a backup
gzip -t "$OUT/db.sql.gz"
tar -tzf "$OUT/storage.tar.gz" > /dev/null
tar -tzf "$OUT/sftpgo.tar.gz" > /dev/null
tar -tzf "$OUT/cryptdaemon-etc.tar.gz" > /dev/null
[ ! -e "$OUT/letsencrypt.tar.gz" ] || tar -tzf "$OUT/letsencrypt.tar.gz" > /dev/null
if ! zcat "$OUT/db.sql.gz" | grep -q 'CREATE TABLE `users`'; then
  echo "ERROR: the database dump has no users table; keeping $OUT for inspection but do not rely on it." >&2
  exit 1
fi

( cd "$OUT" && sha256sum "${parts[@]}" > SHA256SUMS )
echo "Backup written to $OUT"
