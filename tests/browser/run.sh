#!/usr/bin/env bash
# Passkeys in the web UI, end to end in Chromium: the real API (daemon stubbed), the PHP web UI and
# Chromium's virtual authenticator, and the app's sign-in through the approve page. Needs php, node with
# playwright, go, and python with the API's packages.
set -euo pipefail
cd "$(dirname "$0")"
W=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$W"' EXIT
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
API_PORT=$(free_port); WEB_PORT=$(free_port)
export PYTHON=${PYTHON:-python3}
export DATABASE_URL="sqlite:///$W/db.sqlite" JWT_SECRET_KEY=$(openssl rand -hex 32) REFRESH_TOKEN_HMAC_KEY=$(openssl rand -hex 32) \
       TOTP_ENCRYPTION_KEY=$(openssl rand -hex 32) DAEMON_AUTH_KEY=$(openssl rand -hex 32) \
       REQUIRE_EMAIL_VERIFICATION=false REQUIRED_FACTORS=password,totp CHANGE_DELAY_HOURS=0 SMTP_HOST= \
       BASE_URL="http://localhost:$WEB_PORT" API_PORT
(cd ../../cryptclient && GOFLAGS=-mod=mod go build -o "$W/cliapp" ./browserlogin/testapp)
"$PYTHON" api_server.py 2>"$W/api.log" &
API_BASE_URL="http://127.0.0.1:$API_PORT" php -S "localhost:$WEB_PORT" -t ../../webui >"$W/php.log" 2>&1 &
for i in $(seq 1 40); do curl -sf "http://127.0.0.1:$API_PORT/health" >/dev/null && break; sleep 0.5; done
WEB_URL="http://localhost:$WEB_PORT" API_URL="http://127.0.0.1:$API_PORT" CLI_APP="$W/cliapp" NODE_PATH=${NODE_PATH:-$(npm root -g)} node passkey.mjs || { tail -20 "$W/api.log"; echo "== web UI (php -S)"; tail -20 "$W/php.log"; exit 1; }
