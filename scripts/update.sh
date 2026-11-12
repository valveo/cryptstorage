#!/usr/bin/env bash
# cryptstorage-update - Moves a server installed with install.sh to a new CryptStorage version.
#
#   sudo cryptstorage-update              the newest release
#   sudo cryptstorage-update --check      only say which version is installed and which is available
#   sudo cryptstorage-update --full       take a complete backup first, the users' files included
#
# What it does, in this order, stopping at the first thing that fails:
#   1. finds the new version and downloads its server package from the project's releases
#   2. checks the package against the release's signed SHA256SUMS (docs/verify-release.md)
#   3. checks that this server can run it (install.sh --check of the new version)
#   4. takes a backup: the database, the SFTPGo state, the settings and the keys, which is everything
#      an upgrade changes. With --full also the users' encrypted files (needs that much free space)
#   5. installs the new version with the saved settings (install.sh --upgrade)
#   6. checks that the server answers and reports the new version
# Nothing is changed before step 5. It never runs by itself: you start it when the moment suits.
#
# Options:
#   --version X.Y.Z          that version instead of the newest
#   --from DIR               take cryptstorage-server-X.Y.Z.tar.gz, SHA256SUMS and
#                            SHA256SUMS.sigstore.json from DIR instead of downloading (a server
#                            without internet access)
#   --full                   complete backup (cryptstorage-backup), not only what the upgrade changes
#   --backup-dir DIR         where the backup goes (default /var/backups/cryptstorage)
#   --no-signature-check     go on without cosign. The package is then only as trustworthy as the
#                            place it was downloaded from
#   --yes                    do not ask for confirmation
#   --check                  change nothing
#
# Environment: CRYPTSTORAGE_RELEASES (download address, default the project's GitHub releases),
#              CRYPTSTORAGE_RELEASES_API (list of releases)
# See docs/UPGRADE.md, including how to go back.
set -euo pipefail

main() {
  local ETC="${CRYPTSTORAGE_ETC:-/etc/cryptstorage}"
  local STATE="${CRYPTSTORAGE_STATE:-/var/lib/cryptstorage}"
  local RELEASES="${CRYPTSTORAGE_RELEASES:-https://github.com/valveo/cryptstorage/releases/download}"
  local API="${CRYPTSTORAGE_RELEASES_API:-https://api.github.com/repos/valveo/cryptstorage/releases?per_page=30}"
  local BACKUP_CMD="${CRYPTSTORAGE_BACKUP_CMD:-cryptstorage-backup}"
  local HEALTH_URL="${CRYPTSTORAGE_HEALTH_URL:-http://localhost:8000/health}"
  local HEALTH_WAIT="${CRYPTSTORAGE_HEALTH_WAIT:-180}"
  local SIGNER_REPO="https://github.com/valveo/cryptstorage"
  local INVENTORY="$ETC/inventory.yml"

  local VERSION="" FROM="" FULL=0 BACKUP_DIR="/var/backups/cryptstorage" SIGCHECK=1 YES=0 CHECK=0

  say() { printf '%s\n' "$*"; }
  die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

  while [ $# -gt 0 ]; do
    case "$1" in
      --version) VERSION="${2:?}"; VERSION="${VERSION#v}"; shift 2 ;;
      --from) FROM="${2:?}"; shift 2 ;;
      --full) FULL=1; shift ;;
      --backup-dir) BACKUP_DIR="${2:?}"; shift 2 ;;
      --no-signature-check) SIGCHECK=0; shift ;;
      --yes) YES=1; shift ;;
      --check) CHECK=1; shift ;;
      -h|--help) sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
      *) die "unknown option: $1 (see --help)" ;;
    esac
  done

  [ "$(id -u)" = 0 ] || [ -n "${CRYPTSTORAGE_SKIP_SYSTEM_CHECKS:-}" ] || die "run it as root: sudo cryptstorage-update"
  [ -f "$INVENTORY" ] || die "$INVENTORY is missing: this server was not installed with install.sh, so its settings live on the machine it is deployed from. Update it from there (docs/UPGRADE.md)."

  # x.y.z of a version line such as "0.1.2 (2026-11-12)"; nothing for a development build
  release_of() { sed -n 's/^v\{0,1\}\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' <<<"$1" | head -n1; }
  newer() {   # newer A B: is A a later version than B?
    [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1)" = "$1" ]
  }

  local installed_line installed
  installed_line=$(cat "$ETC/installed-version" 2>/dev/null || echo unknown)
  installed=$(release_of "$installed_line")

  # ---- 1. which version ------------------------------------------------------------------------
  if [ -z "$VERSION" ] && [ -n "$FROM" ]; then
    local found
    found=$(find "$FROM" -maxdepth 1 -name 'cryptstorage-server-*.tar.gz' 2>/dev/null | sort -V | tail -n1)
    [ -n "$found" ] || die "no cryptstorage-server-X.Y.Z.tar.gz in $FROM"
    VERSION=$(basename "$found" .tar.gz); VERSION=${VERSION#cryptstorage-server-}
  fi
  if [ -z "$VERSION" ]; then
    # the highest version among the published releases (pre-releases count: before 1.0 all are)
    VERSION=$(curl -fsSL --proto '=https,file' -H 'Accept: application/vnd.github+json' "$API" | python3 -c '
import json, re, sys
best = None
for r in json.load(sys.stdin):
    m = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", r.get("tag_name") or "")
    if m and not r.get("draft"):
        v = tuple(int(x) for x in m.groups())
        best = max(best, v) if best else v
print(".".join(map(str, best)) if best else "")
') || die "could not read the list of releases from $API. Give the version yourself: --version X.Y.Z"
    [ -n "$VERSION" ] || die "no published release found at $API"
  fi
  [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "'$VERSION' is not a version number (X.Y.Z)"

  say "Installed: $installed_line"
  say "Available: $VERSION"
  if [ -n "$installed" ]; then
    if [ "$installed" = "$VERSION" ]; then
      say "This server already runs $VERSION. Nothing to do."
      exit 0
    fi
    newer "$VERSION" "$installed" || die "$VERSION is older than the installed $installed. Going back needs the backup taken before the upgrade: docs/UPGRADE.md, \"Going back\"."
  fi
  if [ "$CHECK" = 1 ]; then
    say "An update is available. Read the changelog entries between the two versions, then run: sudo cryptstorage-update"
    exit 0
  fi

  if [ "$YES" = 0 ]; then
    say ""
    say "This will back up $([ "$FULL" = 1 ] && echo "everything, the users' files included," || echo "the database, settings and keys") to $BACKUP_DIR"
    say "and then install CryptStorage $VERSION. Connected users lose the connection for a moment."
    say "Have you read the changelog entries between the two versions?"
    local answer
    read -r -p "Continue? [y/N] " answer || answer=""
    case "$answer" in y|Y|yes|YES) ;; *) die "stopped, nothing was changed" ;; esac
  fi

  # ---- 2. download and verify ------------------------------------------------------------------
  local pkg="cryptstorage-server-$VERSION.tar.gz" work tree
  mkdir -p "$STATE/releases"; chmod 700 "$STATE"
  work=$(mktemp -d "$STATE/releases/.download.XXXXXX")
  trap "rm -rf '$work'" EXIT
  tree="$STATE/releases/$VERSION"

  fetch() {   # fetch <file>: from --from, or from the release
    if [ -n "$FROM" ]; then
      cp "$FROM/$1" "$work/$1" 2>/dev/null
    else
      curl -fsSL --proto '=https,file' --retry 3 -o "$work/$1" "$RELEASES/v$VERSION/$1"
    fi
  }
  say ""
  say "Getting $pkg..."
  fetch "$pkg" || die "could not get $pkg. Releases before 0.1.3 have no server package: update those as docs/UPGRADE.md says."
  fetch SHA256SUMS || die "the release has no SHA256SUMS"

  ( cd "$work" && grep -E "^[0-9a-f]{64} [ *]$pkg\$" SHA256SUMS > sum.one && sha256sum -c --quiet sum.one ) \
    || die "$pkg does not match the release's SHA256SUMS: damaged or tampered with. Nothing was changed."
  say "  checksum matches SHA256SUMS"

  if [ "$SIGCHECK" = 1 ]; then
    command -v cosign >/dev/null 2>&1 || die "cosign is not installed, so the release signature cannot be checked. install.sh installs it (run it again), or see docs/verify-release.md. To go on without the check, trusting the download address alone: --no-signature-check. Nothing was changed."
    fetch SHA256SUMS.sigstore.json || die "the release has no SHA256SUMS.sigstore.json"
    cosign verify-blob --bundle "$work/SHA256SUMS.sigstore.json" \
      --certificate-identity "$SIGNER_REPO/.github/workflows/release.yml@refs/tags/v$VERSION" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      "$work/SHA256SUMS" >/dev/null 2>"$work/cosign.err" \
      || { cat "$work/cosign.err" >&2; die "the signature of SHA256SUMS is not valid for release v$VERSION. Nothing was changed."; }
    say "  signature is valid: built by the project's release workflow from tag v$VERSION"
  else
    say "  WARNING: signature not checked (--no-signature-check)"
  fi

  rm -rf "$tree.new"; mkdir "$tree.new"
  tar -xzf "$work/$pkg" -C "$tree.new" --strip-components=1 --no-same-owner
  [ -x "$tree.new/install.sh" ] && [ -f "$tree.new/VERSION" ] || { rm -rf "$tree.new"; die "$pkg is not a CryptStorage server package"; }
  rm -rf "$tree"; mv "$tree.new" "$tree"

  # ---- 3. can this server run it ---------------------------------------------------------------
  say ""
  "$tree/install.sh" --check || die "the new version cannot be installed here (see above). Nothing was changed."

  # ---- 4. backup -------------------------------------------------------------------------------
  local storage backup_args=() need have backup_log backup_path
  storage=$(sed -n 's/^ *storage_dir: *"\{0,1\}\([^"#]*[^"# ]\)"\{0,1\}.*/\1/p' "$INVENTORY" | head -n1)
  storage=${storage:-/srv/cryptstorage}
  mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"
  if [ "$FULL" = 1 ]; then
    # ciphertext does not compress: the copy is as large as the original
    need=$(du -sm "$storage" 2>/dev/null | awk '{print $1}'); need=${need:-0}
    have=$(df -Pm "$BACKUP_DIR" | awk 'NR == 2 {print $4}')
    [ "$have" -gt $((need + need / 10 + 200)) ] || die "a complete backup needs about $need MB in $BACKUP_DIR, which has $have MB free. Give another place with --backup-dir, or leave --full out and make sure your regular backup is current. Nothing was changed."
  else
    backup_args+=(--without-files)
  fi
  say ""
  say "Backing up before the upgrade..."
  backup_log="$work/backup.log"
  STORAGE_DIR="$storage" "$BACKUP_CMD" "${backup_args[@]}" "$BACKUP_DIR" 2>&1 | tee "$backup_log" \
    || die "the backup failed, so the upgrade was not started. Nothing was changed."
  backup_path=$(sed -n 's/^Backup .*written to \(.*\)$/\1/p' "$backup_log" | tail -n1)
  [ -n "$backup_path" ] && [ -f "$backup_path/SHA256SUMS" ] || die "the backup did not report where it was written, so the upgrade was not started. Nothing was changed."

  going_back() {
    say "  Backup taken before the upgrade: $backup_path"
    if [ "$FULL" = 0 ]; then
      say "  (database, settings and keys; the users' files stayed in $storage and are not in it)"
    fi
    say "  Going back to $installed_line: docs/UPGRADE.md, \"Going back\"."
  }

  # ---- 5. install ------------------------------------------------------------------------------
  say ""
  if ! "$tree/install.sh" --upgrade; then
    say "" >&2
    say "ERROR: installing $VERSION failed (see above). The server may be partly upgraded." >&2
    say "  Fix the cause and run this again: $tree/install.sh --upgrade" >&2
    going_back >&2
    exit 1
  fi

  # ---- 6. does it answer -----------------------------------------------------------------------
  local want waited=0 got=""
  want=$(cat "$tree/VERSION")
  while [ "$waited" -lt "$HEALTH_WAIT" ]; do
    got=$(curl -fsS --max-time 5 "$HEALTH_URL" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("version",""))' 2>/dev/null) || got=""
    [ "$got" = "$want" ] && break
    sleep 3; waited=$((waited + 3))
  done
  say ""
  if [ "$got" != "$want" ]; then
    say "ERROR: $VERSION was installed, but the server does not report it (answer: '${got:-none}', expected '$want')." >&2
    say "  Look at: docker compose -f /opt/cryptstorage/docker-compose.yml logs api    (docs/UPGRADE.md)" >&2
    going_back >&2
    exit 1
  fi
  say "CryptStorage $want is running."
  going_back
  say "  Sign in with one account and open its storage before you call it done. Then update the apps."

  # older downloaded versions are not needed any more; the one before stays for going back
  local old
  for old in "$STATE/releases"/*/; do
    old=$(basename "$old")
    [ "$old" = "$VERSION" ] || [ "$old" = "$installed" ] || rm -rf "${STATE:?}/releases/$old"
  done
}

main "$@"
exit
