#!/usr/bin/env bash
# End-to-end test of the encrypted-storage flow with the real parts: the API in e2ee mode, a real
# SFTPGo (scripts/install_sftpgo.sh), sshfs and gocryptfs. Needs root (installs SFTPGo), FUSE, and:
#   ssh-keygen sshfs gocryptfs fusermount python3 go curl
# Run from the repository root:  sudo scripts/e2ee_integration.sh
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }

# ports can be moved (CI on the test server, whose own API is on 8099)
W=$(mktemp -d); PORT_API=${PORT_API:-8099}; PORT_SFTP=${PORT_SFTP:-2222}
cleanup() {
  set +e
  [ -n "${API_PID:-}" ] && kill "$API_PID" 2>/dev/null
  [ -n "${SFTPGO_PID:-}" ] && kill "$SFTPGO_PID" 2>/dev/null
  rm -rf "$W" "$DATA"
}
trap cleanup EXIT

# SFTPGo as the deployment configures it: public-key SFTP only, REST API on loopback, no web interfaces.
# All test clients connect from 127.0.0.1, in parallel, so the per-address connection limit (20) is raised.
scripts/install_sftpgo.sh
DATA=$(mktemp -d); chmod 0755 "$DATA"
mkdir -p "$W/sg"; for d in templates static openapi; do ln -s /usr/share/sftpgo/$d "$W/sg/$d"; done
ssh-keygen -q -t ed25519 -N '' -f "$W/sg/hostkey" </dev/null
SFTPGO_ADMIN_PASSWORD=$(openssl rand -hex 16); SFTPGO_API_PORT=${SFTPGO_API_PORT:-8089}
export SFTPGO_ADMIN_PASSWORD SFTPGO_API_URL="http://127.0.0.1:$SFTPGO_API_PORT" CRYPTSTORAGE_DATA_BASE="$DATA" \
       SFTPGO_UID=$(id -u) SFTPGO_GID=$(id -g)
env SFTPGO_CONFIG_DIR="$W/sg" SFTPGO_LOG_FILE_PATH= SFTPGO_DATA_PROVIDER__DRIVER=sqlite SFTPGO_DATA_PROVIDER__NAME="$W/sg/db" \
    SFTPGO_DATA_PROVIDER__CREATE_DEFAULT_ADMIN=1 SFTPGO_DEFAULT_ADMIN_USERNAME=cryptstorage SFTPGO_DEFAULT_ADMIN_PASSWORD="$SFTPGO_ADMIN_PASSWORD" \
    SFTPGO_SFTPD__BINDINGS__0__PORT=$PORT_SFTP SFTPGO_SFTPD__BINDINGS__0__ADDRESS=127.0.0.1 SFTPGO_SFTPD__HOST_KEYS="$W/sg/hostkey" \
    SFTPGO_SFTPD__PASSWORD_AUTHENTICATION=0 SFTPGO_SFTPD__KEYBOARD_INTERACTIVE_AUTHENTICATION=0 \
    SFTPGO_HTTPD__BINDINGS__0__PORT=$SFTPGO_API_PORT SFTPGO_HTTPD__BINDINGS__0__ADDRESS=127.0.0.1 \
    SFTPGO_HTTPD__BINDINGS__0__ENABLE_WEB_ADMIN=0 SFTPGO_HTTPD__BINDINGS__0__ENABLE_WEB_CLIENT=0 \
    SFTPGO_COMMON__MAX_PER_HOST_CONNECTIONS=200 \
    /usr/bin/sftpgo serve >"$W/sftpgo.log" 2>&1 & SFTPGO_PID=$!
for i in $(seq 1 60); do curl -s "http://127.0.0.1:$SFTPGO_API_PORT/healthz" | grep -q ok && break; sleep 0.5; done

# escrow key pair for policy "both"
eval "$(python3 scripts/escrow.py keygen 2>/dev/null | sed 's/^/export /')"

# the API with the real SFTPGo client behind it
# TOTP_ENCRYPTION_KEY also turns on the stick secrets, so setup seals the stick's key
export JWT_SECRET_KEY=$(openssl rand -hex 32) REFRESH_TOKEN_HMAC_KEY=$(openssl rand -hex 32) TOTP_ENCRYPTION_KEY=$(openssl rand -hex 32) \
       DAEMON_AUTH_KEY=$(openssl rand -hex 32) DATABASE_URL="sqlite:///$W/db.sqlite" \
       RECOVERY_POLICY=both ESCROW_PUBLIC_KEY="$ESCROW_PUBLIC_KEY" \
       REQUIRE_EMAIL_VERIFICATION=false SERVER_HOST=127.0.0.1 SFTP_PORT=$PORT_SFTP PORT=$PORT_API \
       SFTP_HOST_KEY_FILES="$W/sg/hostkey.pub" \
       TRUSTED_PROXIES=127.0.0.0/8
python3 scripts/e2ee_testserver.py 2>"$W/api.log" & API_PID=$!
for i in $(seq 1 40); do curl -sf "http://127.0.0.1:$PORT_API/health" >/dev/null && break; sleep 0.5; done
curl -sf "http://127.0.0.1:$PORT_API/server-info"; echo

( cd cryptclient && CRYPTSTORAGE_IT_URL="http://127.0.0.1:$PORT_API" CRYPTSTORAGE_IT_CIPHER_BASE=$DATA CRYPTSTORAGE_IT_STICK_SECRETS=1 \
    CRYPTSTORAGE_IT_BLOB_OUT="$W/out.txt" go test -count=1 -v -run Integration ./volume ./setup ./syncer )

# the operator can open the user's sealed copy and gets the same recovery code
{ read -r MK; read -r CODE; read -r USER; } < "$W/out.txt"
BLOB=$(python3 - <<PY
import sqlite3
print(sqlite3.connect("$W/db.sqlite").execute("select escrow_blob from users where username=?", ("$USER",)).fetchone()[0])
PY
)
GOT=$(python3 scripts/escrow.py recovery-code "$BLOB")
[ "$GOT" = "$CODE" ] && echo "escrow: operator recovery code matches the user's" || { echo "escrow MISMATCH"; exit 1; }
echo "ALL OK"
