#!/usr/bin/env bash
# CI on the self-hosted runner (the LAN test server): sudo there asks for the runner account's password.
# This puts a `sudo` first in PATH that gives it through an askpass helper, from SUDO_PASSWORD (a secret
# set on the job). Does nothing where sudo needs no password (GitHub's runners).
set -euo pipefail
sudo -n true 2>/dev/null && exit 0
[ -n "${SUDO_PASSWORD:-}" ] || { echo "sudo needs a password here and SUDO_PASSWORD is empty"; exit 1; }
D="$RUNNER_TEMP/sudo-bin"; mkdir -p "$D"; chmod 700 "$D"
printf '#!/bin/sh\nprintf "%%s\\n" "$SUDO_PASSWORD"\n' > "$D/askpass"
printf '#!/bin/sh\nSUDO_ASKPASS="%s/askpass" exec /usr/bin/sudo -A "$@"\n' "$D" > "$D/sudo"
chmod 700 "$D/askpass" "$D/sudo"
echo "$D" >> "$GITHUB_PATH"
