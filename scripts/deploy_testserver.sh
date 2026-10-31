#!/usr/bin/env bash
# Installs a CryptStorage END-TO-END ENCRYPTION TEST SERVER on one Ubuntu/Debian machine, natively (no Docker):
#   - the API in e2ee mode (scripts/e2ee_testserver.py: the real API, the real SFTP provisioner in the same
#     process, SQLite, plain HTTP, e-mail verification off)  -> systemd unit cryptstorage-api
#   - SFTPGo (pinned .deb) for the users' SFTP storage, public-key login only -> systemd unit sftpgo
# Meant for testing clients on a LAN. It is NOT the production layout (that is ansible/): the API runs as
# root here, there is no TLS and no e-mail verification.
#
# Usage (as root, with the source tree unpacked at $SRC):
#   SERVER_HOST=test.example.org SFTP_PORT=2223 API_PORT=8099 SRC=/opt/cryptstorage/src ./deploy_testserver.sh
# Safe to run again: secrets and data are kept; code, units and config are refreshed.
# Optional web UI over HTTPS for passkey tests (scripts/testserver_https.sh): set HTTPS_DOMAIN to a DuckDNS
# name and give the DuckDNS token once, in DUCKDNS_TOKEN or in the file /tmp/cryptstorage-duckdns.env
# (DUCKDNS_TOKEN=...; moved away after reading). Later runs keep the domain.
# RESET_DATA=1 starts from empty: accounts (API database), SFTPGo users and stored files are moved to
# /var/lib/cryptstorage-reset-<time>/ (delete that by hand). Secrets, host keys and the certificate stay.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
: "${SERVER_HOST:?set SERVER_HOST to the name or address clients should use}"
SFTP_PORT=${SFTP_PORT:-2223}; API_PORT=${API_PORT:-8099}; SRC=${SRC:-/opt/cryptstorage/src}
[ -f "$SRC/api/main.py" ] || { echo "no source tree in $SRC"; exit 2; }

# A test server installed under the product's earlier name (secdisk): the secrets and settings move
# over; accounts, SFTP users and files start from empty as with RESET_DATA, since the SFTPGo users' homes
# and its admin name changed with the paths. The old data is kept aside.
if [ -e /etc/secdisk ] || [ -e /srv/secdisk ] || [ -e /var/lib/secdisk ] || [ -e /opt/secdisk ] \
   || [ -e /etc/systemd/system/secdisk-api.service ]; then
  echo "== moving over from the name secdisk"
  systemctl disable --now secdisk-api sftpgo 2>/dev/null || true
  rm -f /etc/systemd/system/secdisk-api.service
  if [ -d /etc/secdisk ] && [ ! -e /etc/cryptstorage ]; then
    mv /etc/secdisk /etc/cryptstorage
    rm -f /etc/cryptstorage/sftpgo-admin # a new admin is created with the new name
    # certbot keeps the hook paths with the certificate
    sed -i 's#/etc/secdisk/#/etc/cryptstorage/#g' /etc/letsencrypt/renewal/*.conf 2>/dev/null || true
  fi
  OLD=/var/lib/cryptstorage-reset-$(date +%Y%m%d-%H%M%S); mkdir -p "$OLD"; chmod 0700 "$OLD"
  for f in /etc/secdisk /var/lib/secdisk /var/lib/sftpgo/sftpgo.db* /srv/secdisk; do
    # named after the whole path: /var/lib/secdisk and /srv/secdisk would collide
    if [ -e "$f" ]; then mv "$f" "$OLD/$(echo "${f#/}" | tr / _)"; echo "moved $f"; fi
  done
  echo "old data kept in $OLD"
  rm -rf /opt/secdisk # the old virtual environment and source copy
  rm -f /etc/nginx/sites-enabled/secdisk-https /etc/nginx/sites-available/secdisk-https \
        /etc/php/*/fpm/pool.d/secdisk.conf
  rm -rf /var/www/secdisk
fi
if [ -z "${HTTPS_DOMAIN:-}" ] && [ -f /etc/cryptstorage/https.env ]; then
  HTTPS_DOMAIN=$(sed -n 's/^HTTPS_DOMAIN=//p' /etc/cryptstorage/https.env)
fi
if [ -f /tmp/cryptstorage-duckdns.env ]; then
  DUCKDNS_TOKEN=$(sed -n 's/^DUCKDNS_TOKEN=//p' /tmp/cryptstorage-duckdns.env); rm -f /tmp/cryptstorage-duckdns.env
fi

echo "== packages"
export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=600 update -qq
apt-get -o DPkg::Lock::Timeout=600 install -y -qq python3-venv curl openssl >/dev/null

echo "== python environment"
[ -x /opt/cryptstorage/venv/bin/python ] || python3 -m venv /opt/cryptstorage/venv
/opt/cryptstorage/venv/bin/pip install -q --upgrade pip
/opt/cryptstorage/venv/bin/pip install -q -r "$SRC/api/requirements.txt"

if [ "${RESET_DATA:-0}" = 1 ]; then
  echo "== reset: accounts, SFTP users and files"
  systemctl stop cryptstorage-api sftpgo 2>/dev/null || true
  OLD=/var/lib/cryptstorage-reset-$(date +%Y%m%d-%H%M%S); mkdir -p "$OLD"; chmod 0700 "$OLD"
  for f in /var/lib/cryptstorage/db.sqlite* /var/lib/sftpgo/sftpgo.db* /srv/cryptstorage; do
    if [ -e "$f" ]; then mv "$f" "$OLD/"; echo "moved $f"; fi
  done
  echo "old data kept in $OLD"
fi

echo "== SFTPGo on port $SFTP_PORT"
"$SRC/scripts/install_sftpgo.sh"
# the previous (OpenSSH based) test server, if present
systemctl disable --now secdisk-sshd >/dev/null 2>&1 || true
rm -f /etc/systemd/system/secdisk-sshd.service
mkdir -p /etc/cryptstorage /srv/cryptstorage /var/lib/sftpgo; install -d -m 0700 /var/lib/cryptstorage
SFTPGO_UID=$(id -u sftpgo); SFTPGO_GID=$(id -g sftpgo)
chown sftpgo:sftpgo /srv/cryptstorage; chmod 0755 /srv/cryptstorage
[ -f /etc/cryptstorage/sftpgo-admin ] || { umask 077; openssl rand -hex 24 > /etc/cryptstorage/sftpgo-admin; }
SFTPGO_ADMIN_PASSWORD=$(cat /etc/cryptstorage/sftpgo-admin)
[ -f /var/lib/sftpgo/hostkey_ed25519 ] || { ssh-keygen -q -t ed25519 -N '' -f /var/lib/sftpgo/hostkey_ed25519 </dev/null; chown sftpgo:sftpgo /var/lib/sftpgo/hostkey_ed25519*; }
cat > /etc/sftpgo/sftpgo.env <<ENV
SFTPGO_DATA_PROVIDER__DRIVER=sqlite
SFTPGO_DATA_PROVIDER__NAME=/var/lib/sftpgo/sftpgo.db
SFTPGO_DATA_PROVIDER__CREATE_DEFAULT_ADMIN=1
SFTPGO_DEFAULT_ADMIN_USERNAME=cryptstorage
SFTPGO_DEFAULT_ADMIN_PASSWORD=$SFTPGO_ADMIN_PASSWORD
SFTPGO_SFTPD__BINDINGS__0__PORT=$SFTP_PORT
SFTPGO_SFTPD__BINDINGS__0__ADDRESS=
SFTPGO_SFTPD__HOST_KEYS=/var/lib/sftpgo/hostkey_ed25519
SFTPGO_SFTPD__PASSWORD_AUTHENTICATION=0
SFTPGO_SFTPD__KEYBOARD_INTERACTIVE_AUTHENTICATION=0
SFTPGO_HTTPD__BINDINGS__0__PORT=8080
SFTPGO_HTTPD__BINDINGS__0__ADDRESS=127.0.0.1
SFTPGO_HTTPD__BINDINGS__0__ENABLE_WEB_ADMIN=0
SFTPGO_HTTPD__BINDINGS__0__ENABLE_WEB_CLIENT=0
SFTPGO_COMMON__DEFENDER__ENABLED=1
ENV
chmod 0640 /etc/sftpgo/sftpgo.env; chgrp sftpgo /etc/sftpgo/sftpgo.env
systemctl daemon-reload

echo "== API configuration"
if [ ! -f /etc/cryptstorage/escrow.env ]; then
  ( cd "$SRC" && /opt/cryptstorage/venv/bin/python scripts/escrow.py keygen ) > /etc/cryptstorage/escrow.env
  chmod 0600 /etc/cryptstorage/escrow.env
fi
# shellcheck disable=SC1091
ESCROW_PUBLIC_KEY=$(grep -E '^ESCROW_PUBLIC_KEY=' /etc/cryptstorage/escrow.env | cut -d= -f2-)
if [ ! -f /etc/cryptstorage/api.env ]; then
  umask 077
  cat > /etc/cryptstorage/api.env <<ENV
JWT_SECRET_KEY=$(openssl rand -hex 32)
REFRESH_TOKEN_HMAC_KEY=$(openssl rand -hex 32)
DAEMON_AUTH_KEY=$(openssl rand -hex 32)
TOTP_ENCRYPTION_KEY=$(openssl rand -hex 32)
ENV
fi
cat > /etc/cryptstorage/api.settings <<ENV
DATABASE_URL=sqlite:////var/lib/cryptstorage/db.sqlite
RECOVERY_POLICY=both
ESCROW_PUBLIC_KEY=$ESCROW_PUBLIC_KEY
REQUIRE_EMAIL_VERIFICATION=false
SERVER_HOST=$SERVER_HOST
SFTP_PORT=$SFTP_PORT
SFTP_HOST_KEY_FILES=/var/lib/sftpgo/hostkey_ed25519.pub
SFTPGO_API_URL=http://127.0.0.1:8080
SFTPGO_ADMIN_PASSWORD=$SFTPGO_ADMIN_PASSWORD
CRYPTSTORAGE_DATA_BASE=/srv/cryptstorage
SFTPGO_UID=$SFTPGO_UID
SFTPGO_GID=$SFTPGO_GID
PORT=$API_PORT
HOST=0.0.0.0
TRUSTED_PROXIES=127.0.0.0/8
ENV
# Passkeys are bound to the HTTPS name of the web UI
[ -z "${HTTPS_DOMAIN:-}" ] || echo "BASE_URL=https://$HTTPS_DOMAIN" >> /etc/cryptstorage/api.settings
cat > /etc/systemd/system/cryptstorage-api.service <<UNIT
[Unit]
Description=CryptStorage API (end-to-end test server)
After=network.target sftpgo.service

[Service]
EnvironmentFile=/etc/cryptstorage/api.env
EnvironmentFile=/etc/cryptstorage/api.settings
WorkingDirectory=$SRC/api
ExecStart=/opt/cryptstorage/venv/bin/python $SRC/scripts/e2ee_testserver.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT

# A database made by the old server-side-encryption code has columns the API no longer fills in (NOT NULL
# encrypted_master_key): registration would fail with 500. The test server holds no data worth keeping.
if [ -f /var/lib/cryptstorage/db.sqlite ] && /opt/cryptstorage/venv/bin/python - <<'PY'
import sqlite3, sys
cols = {r[1] for r in sqlite3.connect("/var/lib/cryptstorage/db.sqlite").execute("pragma table_info(users)")}
sys.exit(0 if "encrypted_master_key" in cols else 1)
PY
then
  mv /var/lib/cryptstorage/db.sqlite "/var/lib/cryptstorage/db.sqlite.old-$(date +%s)"; echo "old database moved aside"
fi

echo "== firewall"
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  ufw allow "$SFTP_PORT/tcp" >/dev/null; ufw allow "$API_PORT/tcp" >/dev/null; echo "ufw: opened $SFTP_PORT and $API_PORT"
else echo "ufw not active; nothing to open"; fi

if [ -n "${HTTPS_DOMAIN:-}" ]; then
  echo "== HTTPS web UI"
  HTTPS_DOMAIN=$HTTPS_DOMAIN DUCKDNS_TOKEN=${DUCKDNS_TOKEN:-} API_PORT=$API_PORT SRC=$SRC bash "$SRC/scripts/testserver_https.sh" \
    || echo "WARNING: the HTTPS part failed (see above); the API and SFTP still work"
fi

echo "== start"
systemctl daemon-reload
systemctl enable sftpgo >/dev/null 2>&1
systemctl restart sftpgo cryptstorage-api
systemctl enable cryptstorage-api >/dev/null 2>&1
for i in $(seq 1 40); do curl -sf "http://127.0.0.1:$API_PORT/health" >/dev/null && break; sleep 0.5; done
echo "health: $(curl -s http://127.0.0.1:$API_PORT/health)"
echo "server-info: $(curl -s http://127.0.0.1:$API_PORT/server-info)"
echo "listening: $(ss -ltn | awk 'NR>1{print $4}' | sort -u | tr '\n' ' ')"
systemctl is-active sftpgo cryptstorage-api
