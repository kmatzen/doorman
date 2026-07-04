#!/bin/sh
# doorman one-line installer.
#
#   curl -sSL https://github.com/kmatzen/doorman/releases/latest/download/install.sh | sh
#
# Detects the host platform, downloads the matching release tarball,
# verifies it against the published SHA256SUMS (and against the sigstore
# attestation if `gh` is on PATH), and installs the binary to
# /usr/local/bin/doormand.
#
# Env vars:
#   DOORMAN_VERSION   release tag to install (default: latest)
#   DOORMAN_PREFIX    install dir for the binary (default: /usr/local/bin)

set -eu

REPO="kmatzen/doorman"
PREFIX="${DOORMAN_PREFIX:-/usr/local/bin}"
TAG="${DOORMAN_VERSION:-latest}"

log() { printf 'doorman-install: %s\n' "$*"; }
err() { printf 'doorman-install: error: %s\n' "$*" >&2; exit 1; }

os=$(uname -s)
arch=$(uname -m)
case "$os/$arch" in
  Darwin/arm64)              target="aarch64-apple-darwin" ;;
  Darwin/x86_64)             target="x86_64-apple-darwin" ;;
  Linux/aarch64|Linux/arm64) target="aarch64-unknown-linux-musl" ;;
  Linux/x86_64)              target="x86_64-unknown-linux-musl" ;;
  *) err "unsupported platform: $os/$arch" ;;
esac

if [ "$TAG" = "latest" ]; then
  TAG=$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
         "https://github.com/$REPO/releases/latest")
  TAG="${TAG##*/}"
  [ -z "$TAG" ] && err "could not resolve latest release tag"
fi

version="${TAG#v}"
tarball="doorman-${version}-${target}.tar.gz"
base="https://github.com/$REPO/releases/download/$TAG"

log "platform: $target"
log "version:  $TAG"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

log "downloading $tarball ..."
curl -fsSL -o "$tarball"   "$base/$tarball"   || err "download failed: $base/$tarball"
curl -fsSL -o SHA256SUMS   "$base/SHA256SUMS" || err "download failed: $base/SHA256SUMS"

log "verifying SHA256 ..."
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c SHA256SUMS --ignore-missing >/dev/null || err "SHA256 mismatch"
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 -c SHA256SUMS --ignore-missing >/dev/null || err "SHA256 mismatch"
else
  err "no checksum tool found (need sha256sum or shasum)"
fi

if command -v gh >/dev/null 2>&1; then
  log "verifying sigstore attestation ..."
  if gh attestation verify "$tarball" --repo "$REPO"; then
    log "attestation verified."
  else
    if [ "${DOORMAN_REQUIRE_ATTESTATION:-}" = "1" ]; then
      err "DOORMAN_REQUIRE_ATTESTATION=1 is set; refusing to install"
    fi
    log "warning: gh attestation verify failed (see error above)."
    log "         proceeding with SHA256-only verification — the SHA256SUMS file"
    log "         is itself signed and was checked above. Set"
    log "         DOORMAN_REQUIRE_ATTESTATION=1 to make this a hard error."
    log "         (common cause: gh < 2.49 lacks the 'attestation' subcommand.)"
  fi
else
  log "gh CLI not found; skipped sigstore provenance check."
  log "(install gh ≥ 2.49 and run 'gh attestation verify $tarball --repo $REPO' for full provenance.)"
fi

log "installing to $PREFIX/doormand ..."
tar -xzf "$tarball"
dir="doorman-${version}-${target}"
if [ -w "$PREFIX" ]; then
  install -m 0755 "$dir/doormand" "$PREFIX/doormand"
else
  sudo install -m 0755 "$dir/doormand" "$PREFIX/doormand"
fi

log "installed: $PREFIX/doormand"
log ""
log "next: write a config (see https://github.com/$REPO#config)."
log ""
log "IMPORTANT — run doormand under a DEDICATED service uid, not your login user."
log "  The config holds secrets in plaintext; file permissions keep *other* users out"
log "  but do NOT isolate the secrets from other code (shells, cron, AI agents) running"
log "  as the same uid, which bypasses the proxy entirely (see issue #39). Use the"
log "  service install path, which runs doorman as its own uid:"
log "    Linux:  doormand install-service > /etc/systemd/system/doormand.service   (User=doorman;"
log "            create it first: sudo useradd --system --no-create-home --shell /usr/sbin/nologin doorman)"
log "    macOS:  sudo bash scripts/install-darwin.sh   (creates the _doorman account for you)"
log "  If you start doormand as your own login user anyway, it will warn at each start;"
log "  pass 'run --allow-same-uid' to acknowledge and silence that warning."
