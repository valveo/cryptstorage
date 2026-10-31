#!/bin/bash
# setup-files.sh - Copies the source code into Ansible's files/ directories
# Run this in the ansible/ directory before running the playbook

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "Copying source code into Ansible's files/ directories..."

# the version the API and the web UI show
"$PROJECT_DIR/scripts/version.sh" | tee "$PROJECT_DIR/api/BUILD_VERSION" > "$PROJECT_DIR/webui/BUILD_VERSION"

# cryptdaemon
mkdir -p "$SCRIPT_DIR/roles/cryptdaemon/files/cryptdaemon"
cp "$PROJECT_DIR/cryptdaemon/"*.py "$SCRIPT_DIR/roles/cryptdaemon/files/cryptdaemon/"
echo "  ✓ cryptdaemon"

# api
# socket_auth.py has a single source (cryptdaemon/); the API ships a verbatim copy.
cp "$PROJECT_DIR/cryptdaemon/socket_auth.py" "$PROJECT_DIR/api/socket_auth.py"
mkdir -p "$SCRIPT_DIR/roles/cryptstack/files/api"
cp -r "$PROJECT_DIR/api/"* "$SCRIPT_DIR/roles/cryptstack/files/api/"
echo "  ✓ api"

# webui
mkdir -p "$SCRIPT_DIR/roles/cryptstack/files/webui"
cp -r "$PROJECT_DIR/webui/"* "$SCRIPT_DIR/roles/cryptstack/files/webui/"
echo "  ✓ webui"

# backup script (installed as /usr/local/sbin/cryptstorage-backup)
cp "$PROJECT_DIR/scripts/backup.sh" "$SCRIPT_DIR/roles/cryptstack/files/backup.sh"
echo "  ✓ backup.sh"

echo ""
echo "Done! You can now run the playbook:"
echo "  ansible-playbook -i inventory/my-hosts.yml site.yml"
