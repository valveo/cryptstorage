#!/usr/bin/env bash
# Optional HTTPS part of the end-to-end test server (deploy_testserver.sh): the web UI behind nginx with a
# Let's Encrypt certificate, so passkeys can be tried with a real phone. Passkeys need HTTPS and a
# real name; they do not work on a bare IP address.
#
# The name is a free DuckDNS subdomain. The certificate comes through the DNS challenge (a TXT record set
# with the DuckDNS API), so no port has to be open to the internet. The script points the name at this
# machine's LAN address: a phone and a computer on the same network reach it, nobody outside does.
# Some routers refuse public names that point to a private address ("DNS rebinding protection"); then
# allow the name in the router, or point it at the public address and forward port 443.
#
# Usage (as root, called by deploy_testserver.sh when HTTPS_DOMAIN is set):
#   HTTPS_DOMAIN=mytest.duckdns.org DUCKDNS_TOKEN=... API_PORT=8099 SRC=/opt/cryptstorage/src ./testserver_https.sh
# Optional: HTTPS_IP (default: this machine's LAN address), LETSENCRYPT_EMAIL (expiry notices).
# The token is kept in /etc/cryptstorage/duckdns.env (0600) for the automatic renewals.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
: "${HTTPS_DOMAIN:?set HTTPS_DOMAIN to a DuckDNS name, e.g. mytest.duckdns.org}"
API_PORT=${API_PORT:-8099}; SRC=${SRC:-/opt/cryptstorage/src}
case "$HTTPS_DOMAIN" in
  *.*.duckdns.org) echo "use a DuckDNS name with one label, e.g. mytest.duckdns.org"; exit 2 ;;
  *.duckdns.org) SUB=${HTTPS_DOMAIN%.duckdns.org} ;;
  *) echo "HTTPS_DOMAIN must be a DuckDNS name (*.duckdns.org)"; exit 2 ;;
esac
[[ "$SUB" =~ ^[a-z0-9-]+$ ]] || { echo "bad DuckDNS name: $HTTPS_DOMAIN"; exit 2; }

if [ -n "${DUCKDNS_TOKEN:-}" ]; then
  ( umask 077; printf 'DUCKDNS_TOKEN=%s\n' "$DUCKDNS_TOKEN" > /etc/cryptstorage/duckdns.env )
fi
[ -s /etc/cryptstorage/duckdns.env ] || { echo "no DuckDNS token: set DUCKDNS_TOKEN once"; exit 2; }

echo "== packages (nginx, PHP, certbot)"
export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=600 install -y -qq nginx php-fpm php-mbstring certbot dnsutils curl >/dev/null

echo "== DuckDNS: $HTTPS_DOMAIN"
cat > /etc/cryptstorage/duckdns-hook.sh <<'HOOK'
#!/usr/bin/env bash
# certbot DNS-challenge hook for DuckDNS: "auth" sets the TXT record, "cleanup" clears it
set -euo pipefail
. /etc/cryptstorage/duckdns.env
sub=${CERTBOT_DOMAIN%.duckdns.org}
api="https://www.duckdns.org/update?domains=$sub&token=$DUCKDNS_TOKEN"
if [ "${1:-}" = cleanup ]; then
  curl -fsS "$api&txt=removed&clear=true" >/dev/null || true
  exit 0
fi
[ "$(curl -fsS "$api&txt=$CERTBOT_VALIDATION")" = OK ] || { echo "DuckDNS refused the TXT record (token or name wrong?)" >&2; exit 1; }
# wait until DuckDNS's own name servers answer with the new value
for _ in $(seq 1 30); do
  dig +short TXT "_acme-challenge.$CERTBOT_DOMAIN" @ns1.duckdns.org 2>/dev/null | grep -q -- "$CERTBOT_VALIDATION" && { sleep 5; exit 0; }
  sleep 5
done
echo "TXT record not visible after 150 s; trying anyway" >&2
HOOK
chmod 0700 /etc/cryptstorage/duckdns-hook.sh

IP=${HTTPS_IP:-$(ip -4 route get 1.1.1.1 | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}')}
[ -n "$IP" ] || { echo "could not find this machine's address; set HTTPS_IP"; exit 2; }
# shellcheck disable=SC1091
. /etc/cryptstorage/duckdns.env
[ "$(curl -fsS "https://www.duckdns.org/update?domains=$SUB&token=$DUCKDNS_TOKEN&ip=$IP")" = OK ] \
  || { echo "DuckDNS refused the update: is $SUB created on duckdns.org under the account of this token?"; exit 1; }
echo "$HTTPS_DOMAIN -> $IP"

echo "== certificate"
if [ -n "${LETSENCRYPT_EMAIL:-}" ]; then account=(-m "$LETSENCRYPT_EMAIL"); else account=(--register-unsafely-without-email); fi
certbot certonly --non-interactive --agree-tos "${account[@]}" \
  --manual --preferred-challenges dns \
  --manual-auth-hook "/etc/cryptstorage/duckdns-hook.sh auth" \
  --manual-cleanup-hook "/etc/cryptstorage/duckdns-hook.sh cleanup" \
  --deploy-hook "systemctl reload nginx" \
  --keep-until-expiring -d "$HTTPS_DOMAIN"
# renewals: certbot's own systemd timer (from the package) reuses the hooks stored with the certificate

echo "== web UI"
mkdir -p /var/www/cryptstorage
rm -rf /var/www/cryptstorage/*
cp -r "$SRC/webui/." /var/www/cryptstorage/
rm -f /var/www/cryptstorage/Dockerfile
chown -R root:root /var/www/cryptstorage; chmod -R a+rX /var/www/cryptstorage
FPM_DIR=$(ls -d /etc/php/*/fpm | sort -V | tail -1)
FPM_SERVICE="php$(basename "$(dirname "$FPM_DIR")")-fpm"
cat > "$FPM_DIR/pool.d/cryptstorage.conf" <<POOL
[cryptstorage]
user = www-data
group = www-data
listen = /run/php/cryptstorage-fpm.sock
listen.owner = www-data
listen.group = www-data
pm = ondemand
pm.max_children = 5
env[API_BASE_URL] = http://127.0.0.1:$API_PORT
php_admin_value[session.use_strict_mode] = 1
php_admin_value[session.cookie_httponly] = 1
php_admin_value[session.cookie_secure] = 1
POOL

cat > /etc/nginx/sites-available/cryptstorage-https <<NGINX
# CryptStorage test server: web UI over HTTPS (scripts/testserver_https.sh)
server {
    listen 80;
    listen [::]:80;
    server_name $HTTPS_DOMAIN;
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name $HTTPS_DOMAIN;
    ssl_certificate     /etc/letsencrypt/live/$HTTPS_DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$HTTPS_DOMAIN/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    root /var/www/cryptstorage;
    index index.php;
    location ~ /\. { deny all; }
    location / { try_files \$uri \$uri/ =404; }
    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/cryptstorage-fpm.sock;
    }
}
NGINX
ln -sf /etc/nginx/sites-available/cryptstorage-https /etc/nginx/sites-enabled/cryptstorage-https
nginx -t
systemctl restart "$FPM_SERVICE"
systemctl enable nginx >/dev/null 2>&1
systemctl reload-or-restart nginx

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  ufw allow 443/tcp >/dev/null; echo "ufw: opened 443"
fi
printf 'HTTPS_DOMAIN=%s\n' "$HTTPS_DOMAIN" > /etc/cryptstorage/https.env
echo "web UI: https://$HTTPS_DOMAIN/"
