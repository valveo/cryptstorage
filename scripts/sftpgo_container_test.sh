#!/usr/bin/env bash
# Runs the SFTPGo container of the Ansible stack the way a server does and checks:
#   - the role tasks prepare the state directory and host keys, and the container starts with them
#   - the daemon's client creates a user through the REST API on 127.0.0.1:8081
#   - that user connects with its key on sftp_port, and the host key is the one the API hands out
#   - data and the host key survive a container restart, and a restore as in docs/BACKUP.md
# Needs root, docker with compose, ansible-playbook, ssh/sftp/ssh-keygen and python3 with requests.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
cd "$(dirname "$0")/.."
REPO=$PWD

W=$(mktemp -d); chmod 0755 "$W"
INSTALL=$W/opt/cryptstorage; STORAGE=$W/srv/cryptstorage; PORT=${SFTP_PORT:-2222}
mkdir -p "$INSTALL" "$(dirname "$STORAGE")"
COMPOSE=(docker compose -f "$INSTALL/docker-compose.yml" -p cryptstorage-sftpgo-test)
cleanup() { "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true; rm -rf "$W"; }
trap cleanup EXIT

echo "== role tasks"
ANSIBLE_ROLES_PATH=ansible/roles ansible-playbook -i localhost, ansible/tests/sftpgo-container.yml \
  -e install_dir="$INSTALL" -e storage_dir="$STORAGE" -e sftp_port="$PORT" >"$W/ansible.log" || { cat "$W/ansible.log"; exit 1; }
for k in id_rsa id_ecdsa id_ed25519; do
  [ "$(stat -c %a:%u "$INSTALL/sftpgo/$k")" = "600:$(id -u cryptstorage)" ] || { echo "bad mode/owner on $k"; exit 1; }
  [ "$(stat -c %a "$INSTALL/sftpgo/$k.pub")" = 644 ] || { echo "bad mode on $k.pub"; exit 1; }
done

up() {
  "${COMPOSE[@]}" up -d sftpgo >/dev/null 2>"$W/compose.log" || { cat "$W/compose.log"; exit 1; }
  for i in $(seq 1 60); do curl -s http://127.0.0.1:8081/healthz | grep -q ok && return; sleep 1; done
  "${COMPOSE[@]}" logs sftpgo | tail -20; echo "SFTPGo did not start"; exit 1
}

echo "== start"
up
# the keys the API hands out (SFTP_HOST_KEY_FILES) must be exactly the ones served
cat "$INSTALL"/sftpgo/id_*.pub | awk '{print $1, $2}' | sort > "$W/listed"
ssh-keyscan -p "$PORT" 127.0.0.1 2>/dev/null | grep -v '^#' | awk '{print $2, $3}' | sort > "$W/served"
diff "$W/listed" "$W/served" || { echo "served host keys differ from the .pub files"; exit 1; }
awk -v p="$PORT" '{print "[127.0.0.1]:" p, $0}' "$W/listed" > "$W/known_hosts"

echo "== create a user through the REST API (the daemon's client)"
ssh-keygen -q -t ed25519 -N '' -f "$W/user" </dev/null
export SFTPGO_API_URL=http://127.0.0.1:8081 SFTPGO_ADMIN_PASSWORD_FILE=/etc/cryptdaemon/sftpgo-admin \
       CRYPTSTORAGE_DATA_BASE="$STORAGE" SFTPGO_UID=$(id -u cryptstorage) SFTPGO_GID=$(id -g cryptstorage)
ACCT=$(python3 -c "import sys; sys.path.insert(0, 'cryptdaemon'); import sftpgo_client as s; print(s.provision('ciuser', open('$W/user.pub').read().strip(), 10**9))")
echo "account: $ACCT"

sftp_do() {  # runs sftp commands from stdin as the user, refusing any other host key
  sftp -q -b - -P "$PORT" -i "$W/user" -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$W/known_hosts" \
       -o BatchMode=yes "$ACCT@127.0.0.1"
}

echo "== write"
head -c 100000 /dev/urandom > "$W/payload"
printf 'put %s payload\n' "$W/payload" | sftp_do
check() {
  rm -f "$W/back"
  printf 'get payload %s\n' "$W/back" | sftp_do
  cmp "$W/payload" "$W/back" || { echo "data differs after $1"; exit 1; }
  echo "ok after $1"
}
check "upload"

echo "== restart"
"${COMPOSE[@]}" restart sftpgo >/dev/null
for i in $(seq 1 60); do curl -s http://127.0.0.1:8081/healthz | grep -q ok && break; sleep 1; done
check "restart"

echo "== backup and restore (docs/BACKUP.md, without the database)"
"${COMPOSE[@]}" down >/dev/null 2>&1
tar -C "$(dirname "$STORAGE")" -czf "$W/storage.tar.gz" "$(basename "$STORAGE")"
tar -C "$(dirname "$INSTALL/sftpgo")" -czf "$W/sftpgo.tar.gz" sftpgo
rm -rf "$STORAGE" "$INSTALL/sftpgo"
tar -C "$(dirname "$STORAGE")" -xzf "$W/storage.tar.gz"
tar -C "$INSTALL" -xzf "$W/sftpgo.tar.gz"
up
check "restore"
echo "ALL OK"
