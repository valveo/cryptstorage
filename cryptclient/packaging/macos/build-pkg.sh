#!/bin/bash
# build-pkg.sh - Rakentaa .pkg-asennuspaketin macOS:lle
#
# Usage: ./build-pkg.sh [version]
# Requires: go, Xcode Command Line Tools (pkgbuild, productbuild)
#
# Installs:
#   - cryptclient universal binary (arm64 + amd64)
#   - LaunchAgent that starts the tray app on /Volumes changes
#   - Homebrew sshfs + macFUSE install automation script
set -e

VERSION="${1:-1.0.0}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PAYLOAD="${SCRIPT_DIR}/dist/payload"

echo "==> Building cryptclient.pkg version ${VERSION}..."

# Build the universal binary
cd "${SCRIPT_DIR}/../.."
echo "--> Compiling cryptclient (darwin/amd64)..."
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o "/tmp/cryptclient-amd64" .

echo "--> Compiling cryptclient (darwin/arm64)..."
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o "/tmp/cryptclient-arm64" .

echo "--> Creating universal binary..."
lipo -create -output "${SCRIPT_DIR}/cryptclient" \
    "/tmp/cryptclient-amd64" "/tmp/cryptclient-arm64"
cd "${SCRIPT_DIR}"

# Create the payload directory structure
rm -rf "${PAYLOAD}"
mkdir -p "${PAYLOAD}/usr/local/bin"
mkdir -p "${PAYLOAD}/Library/LaunchAgents"
mkdir -p "${PAYLOAD}/Library/Application Support/CryptStorage"

cp cryptclient "${PAYLOAD}/usr/local/bin/"
chmod 755 "${PAYLOAD}/usr/local/bin/cryptclient"

# LaunchAgent – watches /Volumes changes (USB insertion)
cat > "${PAYLOAD}/Library/LaunchAgents/com.cryptstorage.client.plist" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.cryptstorage.client</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/cryptclient</string>
        <string>tray</string>
        <string>--auto-connect</string>
    </array>
    <key>RunAtLoad</key>
    <false/>
    <key>WatchPaths</key>
    <array>
        <!-- Starts the tray app when a USB stick is inserted -->
        <string>/Volumes</string>
    </array>
    <key>ThrottleInterval</key>
    <integer>2</integer>
    <key>StandardErrorPath</key>
    <string>/tmp/cryptclient.log</string>
</dict>
</plist>
PLIST

# Dependency installer -skripti (Homebrew)
cat > "${PAYLOAD}/Library/Application Support/CryptStorage/install-deps.sh" << 'DEPS'
#!/bin/bash
# Installs macFUSE and sshfs with Homebrew
set -e

echo "Installing CryptStorage dependencies..."

if ! command -v brew &>/dev/null; then
    echo "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

echo "Installing macFUSE..."
brew install --cask macfuse

echo "Installing sshfs..."
brew install gromgit/fuse/sshfs-mac

echo ""
echo "✓ Dependencies installed. macFUSE requires a system restart."
echo "  After restart, run: cryptclient tray"
DEPS
chmod +x "${PAYLOAD}/Library/Application Support/CryptStorage/install-deps.sh"

# postinstall-skripti
mkdir -p "${SCRIPT_DIR}/dist/scripts"
cat > "${SCRIPT_DIR}/dist/scripts/postinstall" << 'POST'
#!/bin/bash
# Load the LaunchAgent for the logged-in user
CURRENT_USER=$(stat -f "%Su" /dev/console)
if [ -n "$CURRENT_USER" ] && [ "$CURRENT_USER" != "root" ]; then
    sudo -u "$CURRENT_USER" \
        launchctl load \
        "/Library/LaunchAgents/com.cryptstorage.client.plist" 2>/dev/null || true
fi

echo ""
echo "CryptStorage installed!"
echo "  Run the dependency installer if this is a fresh install:"
echo "  /Library/Application Support/CryptStorage/install-deps.sh"
echo ""
POST
chmod +x "${SCRIPT_DIR}/dist/scripts/postinstall"

# Build the component package
mkdir -p "${SCRIPT_DIR}/dist"
pkgbuild \
    --root "${PAYLOAD}" \
    --scripts "${SCRIPT_DIR}/dist/scripts" \
    --identifier "com.cryptstorage.client" \
    --version "${VERSION}" \
    --install-location "/" \
    "${SCRIPT_DIR}/dist/cryptclient-${VERSION}-component.pkg"

# Create distribution.xml for a user-friendly installer dialog
cat > "${SCRIPT_DIR}/dist/distribution.xml" << DIST
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>CryptStorage Client ${VERSION}</title>
    <welcome file="welcome.html" mime-type="text/html" />
    <readme file="readme.html" mime-type="text/html" />
    <conclusion file="conclusion.html" mime-type="text/html" />
    <pkg-ref id="com.cryptstorage.client" />
    <options customize="never" require-scripts="false" />
    <choices-outline>
        <line choice="default">
            <line choice="com.cryptstorage.client" />
        </line>
    </choices-outline>
    <choice id="default" />
    <choice id="com.cryptstorage.client" visible="false">
        <pkg-ref id="com.cryptstorage.client" />
    </choice>
    <pkg-ref id="com.cryptstorage.client"
             version="${VERSION}"
             auth="root">cryptclient-${VERSION}-component.pkg</pkg-ref>
</installer-gui-script>
DIST

# HTML pages for the installer dialog
cat > "${SCRIPT_DIR}/dist/welcome.html" << HTML
<html><body style="font-family:sans-serif">
<h2>Welcome to CryptStorage Client</h2>
<p>This will install the CryptStorage encrypted storage client.</p>
<p><b>After installation:</b></p>
<ol>
  <li>Run the dependency installer from Applications</li>
  <li>Restart your Mac (required for macFUSE)</li>
  <li>Run <code>cryptclient init-usb</code> to initialize your USB key</li>
  <li>Plug in your USB key to connect</li>
</ol>
</body></html>
HTML

cat > "${SCRIPT_DIR}/dist/conclusion.html" << HTML
<html><body style="font-family:sans-serif">
<h2>Installation Complete</h2>
<p>CryptStorage Client has been installed.</p>
<p>Open Terminal and run:<br><code>/Library/Application Support/CryptStorage/install-deps.sh</code></p>
<p>Then restart your Mac.</p>
</body></html>
HTML

cat > "${SCRIPT_DIR}/dist/readme.html" << HTML
<html><body style="font-family:sans-serif">
<h2>Requirements</h2>
<ul>
  <li>macOS 12 (Monterey) or later</li>
  <li>macFUSE (installed automatically)</li>
  <li>sshfs (installed automatically)</li>
  <li>A CryptStorage USB key</li>
</ul>
</body></html>
HTML

# Build the final .pkg
productbuild \
    --distribution "${SCRIPT_DIR}/dist/distribution.xml" \
    --resources "${SCRIPT_DIR}/dist" \
    --package-path "${SCRIPT_DIR}/dist" \
    "${SCRIPT_DIR}/dist/CryptStorageClient-${VERSION}.pkg"

# Clean up temporary files
rm -f "${SCRIPT_DIR}/dist/cryptclient-${VERSION}-component.pkg"

echo ""
echo "✓ Built: dist/CryptStorageClient-${VERSION}.pkg"
echo "  Note: Sign with 'productsign --sign <Developer ID>' before distribution."
echo "  Notarize with 'xcrun notarytool' for Gatekeeper approval."
