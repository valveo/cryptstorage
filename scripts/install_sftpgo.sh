#!/usr/bin/env bash
# Installs the pinned SFTPGo release (the .deb from the project's GitHub release), verifying its SHA-256.
# SFTPGo is AGPL-3.0 (see NOTICE of the package): https://github.com/drakkan/sftpgo
# The package starts its own default service; callers that configure their own stop it (STOP=1, the default).
set -euo pipefail
VERSION=2.7.6
SHA256=34b66f9316157e44996e251049333476aed6618f3d4c846b0900f9c0abc51c4a   # sftpgo_2.7.6-1_amd64.deb
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
if command -v sftpgo >/dev/null && sftpgo --version 2>/dev/null | grep -qi "^sftpgo $VERSION"; then echo "sftpgo $VERSION already installed"; exit 0; fi
case "$(dpkg --print-architecture)" in amd64) ;; *) echo "only amd64 is pinned"; exit 2;; esac
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
curl -fsSL -o "$T/sftpgo.deb" "https://github.com/drakkan/sftpgo/releases/download/v$VERSION/sftpgo_${VERSION}-1_amd64.deb"
echo "$SHA256  $T/sftpgo.deb" | sha256sum -c - >/dev/null || { echo "checksum mismatch"; exit 1; }
DEBIAN_FRONTEND=noninteractive dpkg -i "$T/sftpgo.deb" >/dev/null
if [ "${STOP:-1}" = 1 ]; then systemctl disable --now sftpgo >/dev/null 2>&1 || true; fi
sftpgo --version | head -1
