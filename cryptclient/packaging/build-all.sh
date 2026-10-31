#!/bin/bash
# build-all.sh - Builds installer packages for all platforms with one command
#
# Usage: ./build-all.sh [version]
# Run on Linux. Requires:
#   - Go (cross-compilation supports all platforms)
#   - dpkg-deb (Linux .deb)
#   - rpm-build (Linux .rpm, optional)
#
# .pkg and .msi are built with their own scripts on macOS/Windows machines.

set -e

VERSION="${1:-1.0.0}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="${SCRIPT_DIR}/.."
DIST_DIR="${SCRIPT_DIR}/dist"

echo "========================================="
echo "  CryptStorage Client build v${VERSION}"
echo "========================================="
echo ""

mkdir -p "${DIST_DIR}"

# Binaries for all platforms
echo "==> Cross-compiling binaries..."

declare -A TARGETS=(
    ["linux-amd64"]="linux/amd64"
    ["linux-arm64"]="linux/arm64"
    ["darwin-amd64"]="darwin/amd64"
    ["darwin-arm64"]="darwin/arm64"
    ["windows-amd64"]="windows/amd64"
)

cd "${ROOT_DIR}"
for name in "${!TARGETS[@]}"; do
    platform="${TARGETS[$name]}"
    OS="${platform%/*}"
    ARCH="${platform#*/}"
    EXT=""
    [ "$OS" = "windows" ] && EXT=".exe"
    OUTPUT="${DIST_DIR}/cryptclient-${name}${EXT}"
    echo "  Building ${name}..."
    GOOS="$OS" GOARCH="$ARCH" go build \
        -ldflags="-s -w -X main.Version=${VERSION}" \
        -o "${OUTPUT}" .
done
cd "${SCRIPT_DIR}"

echo ""
echo "==> Binaries built:"
ls -lh "${DIST_DIR}"/cryptclient-* 2>/dev/null || true

# Linux .deb
echo ""
echo "==> Building Linux .deb..."
if command -v dpkg-deb &>/dev/null; then
    cp "${DIST_DIR}/cryptclient-linux-amd64" linux/cryptclient
    bash linux/build-deb.sh "${VERSION}"
    cp linux/dist/deb/*.deb "${DIST_DIR}/" 2>/dev/null || true
    echo "  ✓ .deb built"
else
    echo "  ⚠  dpkg-deb not found, skipping .deb"
fi

# Linux .rpm
echo ""
echo "==> Building Linux .rpm..."
if command -v rpmbuild &>/dev/null; then
    cp "${DIST_DIR}/cryptclient-linux-amd64" linux/cryptclient
    bash linux/build-rpm.sh "${VERSION}"
    echo "  ✓ .rpm built"
else
    echo "  ⚠  rpmbuild not found, skipping .rpm"
fi

echo ""
echo "========================================="
echo "  Build complete!"
echo "========================================="
echo ""
echo "Artifacts in ${DIST_DIR}:"
ls -lh "${DIST_DIR}/" 2>/dev/null

echo ""
echo "Remaining steps:"
echo "  macOS .pkg:   Run packaging/macos/build-pkg.sh on a Mac"
echo "  Windows installer: built by CI (.github/workflows/windows.yml) from packaging/windows/cryptstorage.iss"
echo "  Signing:"
echo "    macOS:   productsign --sign 'Developer ID Installer: ...' cryptclient.pkg"
echo "    Windows: signtool sign /td sha256 /fd sha256 /a cryptclient.msi"
