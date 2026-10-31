#!/bin/bash
# build-rpm.sh - Builds an .rpm package for Fedora/RHEL/CentOS systems
#
# Usage: ./build-rpm.sh [version]
# Requires: go, rpm-build
set -e

VERSION="${1:-1.0.0}"
RELEASE="1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_ROOT="${SCRIPT_DIR}/dist/rpm/BUILD"

echo "==> Building cryptclient .rpm version ${VERSION}..."

# Build the binary
cd "${SCRIPT_DIR}/../.."
echo "--> Compiling cryptclient (linux/amd64)..."
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o "${SCRIPT_DIR}/cryptclient" .
cd "${SCRIPT_DIR}"

# RPM directory structure
mkdir -p "${BUILD_ROOT}"/{usr/local/bin,etc/udev/rules.d,usr/lib/systemd/user,usr/share/applications}

cp cryptclient "${BUILD_ROOT}/usr/local/bin/"
cp "../../udev/70-cryptclient.rules" "${BUILD_ROOT}/etc/udev/rules.d/"
cp "../../udev/cryptstorage-tray@.service" "${BUILD_ROOT}/usr/lib/systemd/user/"

cat > "${BUILD_ROOT}/usr/share/applications/cryptclient.desktop" << DESKTOP
[Desktop Entry]
Name=CryptStorage
Comment=Encrypted storage client
Exec=/usr/local/bin/cryptclient tray
Icon=drive-harddisk-encrypted
Terminal=false
Type=Application
Categories=Utility;Security;
Actions=weblogin;

[Desktop Action weblogin]
Name=Open account web page
Exec=/usr/local/bin/cryptclient web-login
DESKTOP

# .spec file
mkdir -p "${SCRIPT_DIR}/dist/rpm/SPECS"
cat > "${SCRIPT_DIR}/dist/rpm/SPECS/cryptclient.spec" << SPEC
Name:       cryptclient
Version:    ${VERSION}
Release:    ${RELEASE}%{?dist}
Summary:    CryptStorage encrypted storage client
License:    AGPL-3.0-only
BuildArch:  x86_64

Requires:   gocryptfs, fuse-sshfs, fuse
Recommends: zenity, libnotify

%description
Connects to a CryptStorage server using a USB security key.
Supports automatic USB detection, host key pinning and system tray.

%install
mkdir -p %{buildroot}
cp -r ${BUILD_ROOT}/* %{buildroot}/

%files
%attr(755,root,root) /usr/local/bin/cryptclient
%attr(644,root,root) /etc/udev/rules.d/70-cryptclient.rules
%attr(644,root,root) /usr/lib/systemd/user/cryptstorage-tray@.service
%attr(644,root,root) /usr/share/applications/cryptclient.desktop

%post
udevadm control --reload-rules 2>/dev/null || true
udevadm trigger 2>/dev/null || true

%preun
cryptclient disconnect 2>/dev/null || true
SPEC

# Build the RPM
rpmbuild -bb \
    --define "_topdir ${SCRIPT_DIR}/dist/rpm" \
    --define "_builddir ${BUILD_ROOT}" \
    "${SCRIPT_DIR}/dist/rpm/SPECS/cryptclient.spec"

RPM_FILE=$(find "${SCRIPT_DIR}/dist/rpm/RPMS" -name "*.rpm" | head -1)
mv "$RPM_FILE" "${SCRIPT_DIR}/dist/"
echo ""
echo "✓ Built: dist/cryptclient-${VERSION}-${RELEASE}.x86_64.rpm"
echo "  Install: sudo rpm -i dist/cryptclient-${VERSION}-${RELEASE}.x86_64.rpm"
