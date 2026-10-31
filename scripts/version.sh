#!/usr/bin/env bash
# Prints the version of this source tree, the same way the client shows its own (cryptclient/version.go):
#   1.2.3 (2026-10-29)                at a tag v1.2.3
#   dev+9151441 (2026-10-29)          anywhere else (commit and its date, UTC)
#   dev+9151441-modified (...)        with uncommitted changes
# The deploy writes it to api/BUILD_VERSION and webui/BUILD_VERSION, which the API and the web UI show.
set -euo pipefail
cd "$(dirname "$0")/.."
sha=$(git rev-parse --short=7 HEAD 2>/dev/null) || { echo dev; exit 0; }
date=$(TZ=UTC git log -1 --format=%cd --date=format-local:%Y-%m-%d HEAD)
if tag=$(git describe --tags --exact-match HEAD 2>/dev/null); then
  v=${tag#v}
else
  v="dev+$sha"
fi
git diff --quiet HEAD -- 2>/dev/null || v="$v-modified"
echo "$v ($date)"
