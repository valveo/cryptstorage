#!/bin/bash
# install-udev.sh - Installs the udev rule and the user service that opens the storage when the
# stick is inserted
# Run: sudo ./install-udev.sh

set -e

if [ "$EUID" -ne 0 ]; then
    echo "Run as root: sudo ./install-udev.sh"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Installing cryptclient udev rule..."

# the rule and trigger script of earlier versions
rm -f /etc/udev/rules.d/99-cryptclient.rules /usr/local/bin/cryptclient-udev-trigger.sh
# the service under the product's earlier name
rm -f /etc/systemd/user/secdisk-tray@.service

cp "$SCRIPT_DIR/70-cryptclient.rules" /etc/udev/rules.d/
cp "$SCRIPT_DIR/cryptstorage-tray@.service" /etc/systemd/user/

udevadm control --reload-rules
udevadm trigger --subsystem-match=block

echo "✓ udev rule installed."
echo "  Put the server address in ~/.config/cryptstorage/env (CRYPTSTORAGE_SERVER=https://...),"
echo "  log out and in again, then plug in your cryptkey USB stick."
