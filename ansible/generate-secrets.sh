#!/usr/bin/env bash
# Prints fresh values for the secrets in inventory/hosts.yml.
#
#   ./generate-secrets.sh
#
# Keep the real values out of version control: put them in an Ansible Vault file
# (ansible-vault create inventory/group_vars/all/vault.yml) or encrypt single values with
#   ansible-vault encrypt_string '<value>' --name db_password
# DAEMON_AUTH_KEY is not listed here: the cryptdaemon role generates it on the server.
set -euo pipefail

pw() { openssl rand -base64 48 | tr -d '=+/\n' | cut -c1-32; }

cat << YAML
db_root_password: "$(pw)"
db_password: "$(pw)"
jwt_secret_key: "$(openssl rand -hex 32)"
refresh_token_hmac_key: "$(openssl rand -hex 32)"
totp_encryption_key: "$(openssl rand -hex 32)"
YAML
