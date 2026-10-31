#!/bin/bash
# build.sh - Cross-compile cryptclient for all platforms

set -e

VERSION=$(git describe --tags --always 2>/dev/null || echo "dev")
OUTDIR="dist"

mkdir -p "$OUTDIR"

echo "Building cryptclient $VERSION..."

# Linux amd64
echo "  → linux/amd64"
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o "$OUTDIR/cryptclient-linux-amd64" .

# Linux arm64 (Raspberry Pi, etc.)
echo "  → linux/arm64"
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o "$OUTDIR/cryptclient-linux-arm64" .

# macOS amd64
echo "  → darwin/amd64"
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o "$OUTDIR/cryptclient-darwin-amd64" .

# macOS arm64 (Apple Silicon)
echo "  → darwin/arm64"
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o "$OUTDIR/cryptclient-darwin-arm64" .

# Windows amd64, with the padlock icon and version information (rsrc_windows_amd64.syso)
go run ./packaging/windows/winres -version "${VERSION#v}" -o rsrc_windows_amd64.syso
echo "  → windows/amd64"
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o "$OUTDIR/cryptclient-windows-amd64.exe" .
# the same program as a window program: the padlock next to the clock (tray)
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H=windowsgui" -o "$OUTDIR/CryptStorage-windows-amd64.exe" .

echo ""
echo "Binaries in $OUTDIR/:"
ls -lh "$OUTDIR/"
