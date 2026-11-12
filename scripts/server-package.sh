#!/usr/bin/env bash
# Makes the server package of a release: cryptstorage-server-X.Y.Z.tar.gz, the part of this
# repository a server needs (install.sh, the Ansible roles, the API, the daemon, the web UI, the
# scripts and the documentation) at the current commit, plus a VERSION file in place of the git
# history (scripts/version.sh reads it). cryptstorage-update downloads and installs it.
#
#   scripts/server-package.sh 0.1.3 dist/
#
# The release workflow runs it and lists the result in the signed SHA256SUMS.
set -euo pipefail
version="${1:?usage: server-package.sh <version> <output-directory>}"
out="${2:?usage: server-package.sh <version> <output-directory>}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || { echo "bad version: $version" >&2; exit 1; }
cd "$(dirname "$0")/.."
mkdir -p "$out"
out="$(cd "$out" && pwd)"
date=$(TZ=UTC git log -1 --format=%cd --date=format-local:%Y-%m-%d HEAD)
git archive --format=tar.gz --prefix="cryptstorage-$version/" \
  --add-virtual-file="cryptstorage-$version/VERSION:$version ($date)
" -o "$out/cryptstorage-server-$version.tar.gz" HEAD \
  install.sh ansible api cryptdaemon webui scripts docs README.md CHANGELOG.md LICENSE SECURITY.md
echo "$out/cryptstorage-server-$version.tar.gz"
