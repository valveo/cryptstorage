#!/usr/bin/env bash
# install.sh - Installs CryptStorage on THIS server, or applies changed settings to it.
#
#   sudo ./install.sh                 asks a few questions the first time, then installs
#   sudo ./install.sh --check         only checks that this server can run CryptStorage
#   sudo ./install.sh --yes --domain storage.example.com --email admin@example.com \
#        --smtp-host smtp.example.com --smtp-user u --smtp-password-file /root/smtp.pw --smtp-from u@example.com
#
# It is a thin shell around the Ansible playbook in ansible/ (the same one used to install from another
# machine, ansible/README.md): it checks the server, installs Ansible into a directory of its own,
# writes the settings to /etc/cryptstorage/inventory.yml and runs the playbook against this machine.
# There is no second way of installing to keep in step.
#
# Run it again at any time: it uses the saved settings and only fixes what differs. To change a
# setting, edit /etc/cryptstorage/inventory.yml (all settings: ansible/README.md) and run it again.
# To move to a new version use cryptstorage-update, which takes a backup first (docs/UPGRADE.md).
#
# Options for the first run (later runs read the saved settings):
#   --domain NAME            the server's DNS name, e.g. storage.example.com
#   --email ADDRESS          administrator's address (Let's Encrypt notices)
#   --smtp-host HOST         mail server for confirmations and security notices; --no-smtp for none
#   --smtp-port N            default 587 (465 = TLS from the start)
#   --smtp-user NAME, --smtp-password-file FILE, --smtp-from ADDRESS
#   --registration MODE      open (default) | invite | closed
#   --tls MODE               letsencrypt (default) | selfsigned (tests and closed networks only)
#   --yes                    do not ask anything; fail if something needed is missing
# Always:
#   --check                  preflight only
#   --upgrade                called by cryptstorage-update: no questions, settings must exist
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
ETC="${CRYPTSTORAGE_ETC:-/etc/cryptstorage}"
INVENTORY="$ETC/inventory.yml"
TOOLS="${CRYPTSTORAGE_TOOLS:-/opt/cryptstorage-installer}"
SBIN="${CRYPTSTORAGE_SBIN:-/usr/local/sbin}"
OS_RELEASE="${CRYPTSTORAGE_OS_RELEASE:-/etc/os-release}"
MIN_DISK_MB=5000
MIN_RAM_MB=900

DOMAIN="" EMAIL="" SMTP_HOST="" SMTP_PORT=587 SMTP_USER="" SMTP_PASSWORD="" SMTP_FROM=""
NO_SMTP=0 REGISTRATION="" TLS="letsencrypt" YES=0 CHECK_ONLY=0 UPGRADE=0 WRITE_ONLY=0

say()  { printf '%s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="${2:?}"; shift 2 ;;
    --email) EMAIL="${2:?}"; shift 2 ;;
    --smtp-host) SMTP_HOST="${2:?}"; shift 2 ;;
    --smtp-port) SMTP_PORT="${2:?}"; shift 2 ;;
    --smtp-user) SMTP_USER="${2:?}"; shift 2 ;;
    --smtp-password-file) SMTP_PASSWORD="$(head -n1 "${2:?}")"; shift 2 ;;
    --smtp-from) SMTP_FROM="${2:?}"; shift 2 ;;
    --no-smtp) NO_SMTP=1; shift ;;
    --registration) REGISTRATION="${2:?}"; shift 2 ;;
    --tls) TLS="${2:?}"; shift 2 ;;
    --yes) YES=1; shift ;;
    --check) CHECK_ONLY=1; shift ;;
    --upgrade) UPGRADE=1; YES=1; shift ;;
    --write-settings-only) WRITE_ONLY=1; shift ;;      # for the tests: stop after writing the settings
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

# ------------------------------------------------------------------------------------------------
# 1. Can this server run it?
# ------------------------------------------------------------------------------------------------
problems=0
problem() { printf '  [fail] %s\n' "$*"; problems=$((problems + 1)); }
ok()      { printf '  [ ok ] %s\n' "$*"; }
note()    { printf '  [warn] %s\n' "$*"; }

sshd_port() {   # the port the SSH service listens on, so the firewall keeps it open
  local p=""
  if command -v sshd >/dev/null 2>&1; then
    p=$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2; exit}') || true
  fi
  printf '%s' "${p:-22}"
}

port_owner() {  # the program listening on TCP port $1, or nothing
  ss -ltnpH "sport = :$1" 2>/dev/null | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' | head -n1
}

preflight() {
  say "Checking this server..."
  local id="" ver="" name=""
  if [ -r "$OS_RELEASE" ]; then
    id=$(. "$OS_RELEASE"; printf '%s' "${ID:-}")
    ver=$(. "$OS_RELEASE"; printf '%s' "${VERSION_ID:-0}")
    name=$(. "$OS_RELEASE"; printf '%s' "${PRETTY_NAME:-$id $ver}")
  fi
  local major=${ver%%.*}
  case "$id" in
    ubuntu) [ "${major:-0}" -ge 24 ] && ok "$name" || problem "$name is too old: Ubuntu 24.04 or newer is needed" ;;
    debian) [ "${major:-0}" -ge 12 ] && ok "$name" || problem "$name is too old: Debian 12 or newer is needed" ;;
    *) problem "${name:-this system} is not supported: use Ubuntu 24.04+ or Debian 12+" ;;
  esac

  case "$(uname -m)" in
    x86_64|aarch64) ok "processor $(uname -m)" ;;
    *) problem "processor $(uname -m) is not supported (x86_64 or aarch64)" ;;
  esac

  if [ -d /run/systemd/system ] || [ -n "${CRYPTSTORAGE_SKIP_SYSTEM_CHECKS:-}" ]; then
    ok "systemd"
  else
    problem "systemd is not running here (a container?): CryptStorage needs a real server or VM"
  fi

  local ram disk
  ram=$(awk '/^MemTotal:/ {print int($2 / 1024)}' /proc/meminfo 2>/dev/null || echo 0)
  if [ "$ram" -ge "$MIN_RAM_MB" ]; then ok "memory ${ram} MB"; else
    problem "memory ${ram} MB: at least 1 GB is needed"; fi
  disk=$(df -Pm / | awk 'NR == 2 {print $4}')
  if [ "${disk:-0}" -ge "$MIN_DISK_MB" ]; then ok "free disk space ${disk} MB"; else
    problem "free disk space ${disk:-0} MB on /: at least $MIN_DISK_MB MB is needed (plus what the users will store)"; fi

  # Ports the installation serves on. Our own services from an earlier run are fine.
  local p who
  for p in 80 443 "${SFTP_PORT:-2222}"; do
    who=$(port_owner "$p")
    case "$who" in
      ""|nginx|docker-proxy|sftpgo) ok "port $p${who:+ (already ours: $who)}" ;;
      *) problem "port $p is used by '$who': stop or move that service first" ;;
    esac
  done

  # only before the first certificate: later runs do not ask Let's Encrypt for anything
  if [ -n "$DOMAIN" ] && [ "$TLS" = letsencrypt ] && [ ! -e "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    local addrs mine a hit=0
    addrs=$(getent ahosts "$DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u)
    if [ -z "$addrs" ]; then
      problem "$DOMAIN does not resolve: point its DNS at this server first (Let's Encrypt checks it)"
    else
      mine=$(ip -o addr show scope global 2>/dev/null | awk '{sub(/\/.*/, "", $4); print $4}')
      for a in $addrs; do grep -qxF "$a" <<<"$mine" && hit=1; done
      if [ "$hit" = 1 ]; then ok "$DOMAIN points to this server"; else
        note "$DOMAIN resolves to $(echo $addrs), which is not an address of this machine. Fine behind NAT or a load balancer; otherwise Let's Encrypt will fail."; fi
    fi
  fi

  SSH_PORT=$(sshd_port)
  [ "$SSH_PORT" = 22 ] || note "SSH listens on port $SSH_PORT: the firewall will keep that port open instead of 22"

  if [ "$problems" -gt 0 ]; then
    say ""
    die "$problems problem(s) above must be fixed first. Nothing was changed."
  fi
  say "This server can run CryptStorage."
}

# ------------------------------------------------------------------------------------------------
# 2. Settings
# ------------------------------------------------------------------------------------------------
ask() {   # ask <variable> <question> [default]
  local var=$1 q=$2 def=${3:-} answer
  [ -z "${!var}" ] || return 0
  if [ "$YES" = 1 ]; then
    [ -n "$def" ] || die "missing setting: $q (give it as an option, see --help)"
    printf -v "$var" '%s' "$def"; return 0
  fi
  while :; do
    read -r -p "$q${def:+ [$def]}: " answer || die "no answer"
    answer=${answer:-$def}
    [ -n "$answer" ] && break
  done
  printf -v "$var" '%s' "$answer"
}

yaml() {  # a value as a double-quoted YAML string
  local v=$1
  v=${v//\\/\\\\}; v=${v//\"/\\\"}
  printf '"%s"' "$v"
}

secret() { openssl rand -base64 48 | tr -d '=+/\n' | cut -c1-32; }

collect_settings() {
  say ""
  say "A few questions. The answers are saved in $INVENTORY, which you can edit later."
  ask DOMAIN "The server's DNS name (for example storage.example.com)"
  [[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || die "'$DOMAIN' is not a DNS name"
  ask EMAIL "Administrator's e-mail address (certificate notices)"
  [[ "$EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+$ ]] || die "'$EMAIL' is not an e-mail address"

  if [ "$NO_SMTP" = 0 ] && [ -z "$SMTP_HOST" ] && [ "$YES" = 0 ]; then
    say ""
    say "CryptStorage sends e-mail: to confirm addresses, to set up the authenticator app and to"
    say "warn the owner about changes to the account. Without a mail server the second factor"
    say "cannot be made mandatory. Leave the next answer empty to install without mail."
    read -r -p "Mail server (SMTP host): " SMTP_HOST || true
  fi
  if [ -z "$SMTP_HOST" ]; then
    NO_SMTP=1
  else
    ask SMTP_PORT "SMTP port" 587
    ask SMTP_USER "SMTP user name"
    if [ -z "$SMTP_PASSWORD" ]; then
      [ "$YES" = 0 ] || die "missing setting: --smtp-password-file"
      read -r -s -p "SMTP password: " SMTP_PASSWORD || die "no answer"; echo
    fi
    ask SMTP_FROM "Sender address of the messages" "$SMTP_USER"
  fi

  if [ -z "$REGISTRATION" ] && [ "$YES" = 0 ]; then
    say ""
    say "Who may create an account?"
    say "  open    anyone who reaches the server"
    say "  invite  only people you give an invitation code (cryptstorage-admin invite create)"
    say "  closed  nobody for now"
  fi
  ask REGISTRATION "Registration (open / invite / closed)" open
  case "$REGISTRATION" in open|invite|closed) ;; *) die "registration must be open, invite or closed" ;; esac
  case "$TLS" in letsencrypt|selfsigned) ;; *) die "--tls must be letsencrypt or selfsigned" ;; esac
}

write_inventory() {
  local tmp
  mkdir -p "$ETC"; chmod 700 "$ETC"
  tmp=$(mktemp "$ETC/inventory.XXXXXX")
  chmod 600 "$tmp"
  {
    cat << YAML
# CryptStorage settings of this server, written by install.sh on $(date -u +%Y-%m-%d).
# It holds the server's secrets: keep it private (0600, root) and keep a copy off the server,
# together with the backups (docs/BACKUP.md).
# To change a setting: edit, then run install.sh again. All settings: ansible/README.md.
all:
  hosts:
    cryptstorage:
      ansible_connection: local
      ansible_python_interpreter: /usr/bin/python3
  vars:
    domain: $(yaml "$DOMAIN")
    letsencrypt_email: $(yaml "$EMAIL")
    tls_mode: $TLS
    install_dir: /opt/cryptstorage
    cryptapi_gid: 3000
    ssh_port: ${SSH_PORT:-22}
    # Password logins over SSH stay as they are. Set to true once you sign in with a key.
    ssh_keys_only: false

    registration: $REGISTRATION

YAML
    if [ "$NO_SMTP" = 1 ]; then
      cat << YAML
    # No mail server was given. Users cannot confirm their address or set up the authenticator
    # app without one, so both are off. Add smtp_host, smtp_port, smtp_user, smtp_password and
    # smtp_from, then set require_email_verification "true" and required_factors "password,totp".
    smtp_host: ""
    require_email_verification: "false"
    required_factors: "password"

YAML
    else
      cat << YAML
    smtp_host: $(yaml "$SMTP_HOST")
    smtp_port: $SMTP_PORT
    smtp_user: $(yaml "$SMTP_USER")
    smtp_password: $(yaml "$SMTP_PASSWORD")
    smtp_from: $(yaml "$SMTP_FROM")
    require_email_verification: "true"

YAML
    fi
    cat << YAML
    # Secrets, made for this server. Losing totp_encryption_key disables every user's
    # authenticator app and USB stick: it must be in your copy of this file.
    db_root_password: "$(secret)"
    db_password: "$(secret)"
    jwt_secret_key: "$(openssl rand -hex 32)"
    refresh_token_hmac_key: "$(openssl rand -hex 32)"
    totp_encryption_key: "$(openssl rand -hex 32)"
    jwt_refresh_expire_days: 7
YAML
  } > "$tmp"
  mv "$tmp" "$INVENTORY"
  say "Settings written to $INVENTORY"
}

# ------------------------------------------------------------------------------------------------
# 3. Ansible, in a directory of its own, and the playbook against this machine
# ------------------------------------------------------------------------------------------------
install_ansible() {
  say ""
  say "Installing the tools the installation needs..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get -o DPkg::Lock::Timeout=600 update -qq
  apt-get -o DPkg::Lock::Timeout=600 install -y -qq python3 python3-venv openssl curl ca-certificates iproute2 >/dev/null
  if [ ! -x "$TOOLS/venv/bin/ansible-playbook" ]; then
    mkdir -p "$TOOLS"
    python3 -m venv "$TOOLS/venv"
  fi
  # the newest ansible-core of these series that this system's Python supports
  "$TOOLS/venv/bin/pip" install -q --upgrade 'ansible-core>=2.18,<2.21'
  ANSIBLE_COLLECTIONS_PATH="$TOOLS/collections" "$TOOLS/venv/bin/ansible-galaxy" collection install \
    -r "$SRC/ansible/requirements.yml" -p "$TOOLS/collections" >/dev/null
}

run_playbook() {
  say ""
  say "Installing CryptStorage $("$SRC/scripts/version.sh"). This takes several minutes the first time."
  ( cd "$SRC/ansible" && ./setup-files.sh >/dev/null &&
    ANSIBLE_COLLECTIONS_PATH="$TOOLS/collections" ANSIBLE_ROLES_PATH="$SRC/ansible/roles" \
      "$TOOLS/venv/bin/ansible-playbook" -i "$INVENTORY" site.yml )
}

install_update_command() {
  install -m 0750 -o root -g root "$SRC/scripts/update.sh" "$SBIN/cryptstorage-update"
  mkdir -p "$ETC"
  "$SRC/scripts/version.sh" > "$ETC/installed-version"
}

# ------------------------------------------------------------------------------------------------
[ "$(id -u)" = 0 ] || [ -n "${CRYPTSTORAGE_SKIP_SYSTEM_CHECKS:-}" ] || die "run it as root: sudo $0"

if [ -f "$INVENTORY" ]; then
  # the saved settings decide; the port and the domain are needed for the checks
  DOMAIN=$(sed -n 's/^ *domain: *"\{0,1\}\([^"]*\)"\{0,1\} *$/\1/p' "$INVENTORY" | head -n1)
  TLS=$(sed -n 's/^ *tls_mode: *\([a-z]*\).*/\1/p' "$INVENTORY" | head -n1); TLS=${TLS:-letsencrypt}
  SFTP_PORT=$(sed -n 's/^ *sftp_port: *\([0-9]*\).*/\1/p' "$INVENTORY" | head -n1)
  MIN_DISK_MB=2000    # an installed server needs room for the new images only
elif [ -e "${CRYPTSTORAGE_INSTALL_DIR:-/opt/cryptstorage}/docker-compose.yml" ]; then
  # New settings would mean new secrets, and those would lock the existing database and every user out.
  die "CryptStorage is already installed here, but $INVENTORY is missing: it was installed from another machine with Ansible. Keep updating it from there, or move its settings here first (ansible/README.md, \"Moving the settings onto the server\"). Nothing was changed."
fi

preflight
[ "$CHECK_ONLY" = 0 ] || exit 0

if [ -f "$INVENTORY" ]; then
  say ""
  say "Using the saved settings in $INVENTORY."
else
  [ "$UPGRADE" = 0 ] || die "$INVENTORY is missing: this server was not installed with install.sh. Update it the way it was installed (docs/UPGRADE.md)."
  collect_settings
  # the domain was not known at the first check
  if [ "$TLS" = letsencrypt ] && ! getent ahosts "$DOMAIN" >/dev/null 2>&1; then
    die "$DOMAIN does not resolve: point its DNS at this server first (Let's Encrypt checks it). Nothing was changed."
  fi
  write_inventory
fi
[ "$WRITE_ONLY" = 0 ] || exit 0

install_ansible
run_playbook
install_update_command

say ""
say "CryptStorage is installed: https://$DOMAIN"
say "  Settings and secrets:  $INVENTORY   (keep a copy off the server)"
say "  Accounts, invitations: cryptstorage-admin --help"
say "  Backups:               cryptstorage-backup /srv/backups        (docs/BACKUP.md)"
say "  New versions:          cryptstorage-update                     (docs/UPGRADE.md)"
if grep -q '^ *smtp_host: ""' "$INVENTORY"; then
  say ""
  warn "No mail server is set: the authenticator app is optional and addresses are not confirmed. Add the SMTP settings to $INVENTORY and run install.sh again."
fi
if [ "$TLS" = selfsigned ]; then
  warn "The certificate is self-signed: for tests and closed networks only."
fi
