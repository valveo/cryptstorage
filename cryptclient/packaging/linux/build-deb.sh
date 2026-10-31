#!/bin/bash
# build-deb.sh - Builds a .deb package for Ubuntu/Debian systems
#
# Usage: ./build-deb.sh [version]
# Requires: go, dpkg-deb (no go with CRYPTCLIENT_BIN=<prebuilt linux/amd64 binary>)
#
# Installs automatically:
#   - the cryptclient binary
#   - the udev rule for USB auto-detection
#   - the user service it starts (cryptstorage-tray@.service)
# Dependencies are installed with apt (gocryptfs, sshfs, fuse3)
set -e

VERSION="${1:-1.0.0}"
ARCH="amd64"
PKG="cryptclient_${VERSION}_${ARCH}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="${SCRIPT_DIR}/dist/deb/${PKG}"

echo "==> Building cryptclient .deb version ${VERSION}..."

# Build the binary, or package one built elsewhere (CRYPTCLIENT_BIN, e.g. cross-compiled on Windows)
if [ -n "${CRYPTCLIENT_BIN:-}" ]; then
  echo "--> Using ${CRYPTCLIENT_BIN}"
  cp "${CRYPTCLIENT_BIN}" "${SCRIPT_DIR}/cryptclient"
else
  cd "${SCRIPT_DIR}/../.."
  echo "--> Compiling cryptclient (linux/amd64)..."
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -o "${SCRIPT_DIR}/cryptclient" .
fi
cd "${SCRIPT_DIR}"

# Create the package directory structure
rm -rf "${ROOT}"
mkdir -p "${ROOT}/usr/local/bin"
mkdir -p "${ROOT}/etc/udev/rules.d"
mkdir -p "${ROOT}/usr/lib/systemd/user"
mkdir -p "${ROOT}/usr/share/doc/cryptclient"
mkdir -p "${ROOT}/usr/share/applications"
mkdir -p "${ROOT}/DEBIAN"

# Copy files
cp cryptclient "${ROOT}/usr/local/bin/cryptclient"
chmod 755 "${ROOT}/usr/local/bin/cryptclient"

cp "../../udev/70-cryptclient.rules" "${ROOT}/etc/udev/rules.d/"
cp "../../udev/cryptstorage-tray@.service" "${ROOT}/usr/lib/systemd/user/"

# .desktop file launchers
cat > "${ROOT}/usr/share/applications/cryptclient.desktop" << DESKTOP
[Desktop Entry]
Name=CryptStorage
Comment=Encrypted storage client
Exec=/usr/local/bin/cryptclient tray
Icon=drive-harddisk-encrypted
Terminal=false
Type=Application
Categories=Utility;Security;
Keywords=encrypt;storage;usb;
Actions=weblogin;

[Desktop Action weblogin]
Name=Open account web page
Exec=/usr/local/bin/cryptclient web-login
DESKTOP

# Docs
cp "../../../LICENSE" "${ROOT}/usr/share/doc/cryptclient/copyright"

# DEBIAN/control
cat > "${ROOT}/DEBIAN/control" << CTRL
Package: cryptclient
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: CryptStorage <admin@example.com>
Depends: gocryptfs, sshfs, fuse3
Recommends: zenity, libnotify-bin
Description: CryptStorage encrypted storage client
 Connects to a CryptStorage server using a USB security key.
 .
 Features:
  - USB key detection and auto-connect
  - Client-side encryption (gocryptfs); the server stores only ciphertext
  - Host key and TLS pinning (MITM protection)
  - Desktop dialogs when the stick is plugged in (requires zenity)
  - Automatic disconnect on USB removal
CTRL

# DEBIAN/postinst
cat > "${ROOT}/DEBIAN/postinst" << 'POSTINST'
#!/bin/sh
set -e
case "$1" in
    configure)
        udevadm control --reload-rules 2>/dev/null || true
        udevadm trigger 2>/dev/null || true
        echo ""
        echo "cryptclient installed successfully!"
        echo "  1. Run 'cryptclient setup': account, USB stick, storage and recovery code, step by step"
        echo "  2. Then plug in the stick (or run 'cryptclient connect') to open the storage"
        echo ""
        ;;
esac
exit 0
POSTINST
chmod 755 "${ROOT}/DEBIAN/postinst"

# DEBIAN/prerm
cat > "${ROOT}/DEBIAN/prerm" << 'PRERM'
#!/bin/sh
set -e
case "$1" in
    remove|purge)
        cryptclient disconnect 2>/dev/null || true
        ;;
esac
exit 0
PRERM
chmod 755 "${ROOT}/DEBIAN/prerm"

# Build the package
mkdir -p "${SCRIPT_DIR}/dist/deb"
dpkg-deb --build --root-owner-group "${ROOT}" "${SCRIPT_DIR}/dist/deb/${PKG}.deb"
echo ""
echo "✓ Built: dist/deb/${PKG}.deb"
echo "  Install: sudo apt install ./dist/deb/${PKG}.deb"
