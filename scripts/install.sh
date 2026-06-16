#!/usr/bin/env bash
# XPanel one-shot installer (aaPanel-style: curl -fsSL .../install.sh | bash).
# Installs the binary to /usr/local/bin/xpanel, sets up /opt/xpanel as the data
# dir, installs a systemd unit, starts the service, and prints the first-run
# admin credentials scraped from the service log.
#
# Modes:
#   (default)        use a release .tar.gz next to this script, or download one
#   --from-source    build from local/cloned source via build-release.sh
set -euo pipefail

REPO="${XPANEL_REPO:-MevYu/XPanel-Go}"
VERSION="${VERSION:-0.0.1}"
BIN_PATH="/usr/local/bin/xpanel"
DATA_DIR="/opt/xpanel"
UNIT_PATH="/etc/systemd/system/xpanel.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
FROM_SOURCE=0
WITH_FLEET=0

for arg in "$@"; do
  case "$arg" in
    --from-source) FROM_SOURCE=1 ;;
    --fleet)       WITH_FLEET=1 ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

die() { echo "error: $*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || die "must run as root (XPanel manages the host)"

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) die "unsupported arch: $(uname -m)" ;;
  esac
}
ARCH="$(detect_arch)"
SUFFIX=""; [[ "$WITH_FLEET" -eq 1 ]] && SUFFIX="-fleet"

install_binary() {
  # 1) binary already staged next to this script (extracted tarball)
  if [[ -f "$SCRIPT_DIR/xpanel" ]]; then
    echo ">> installing bundled binary"
    install -m 0755 "$SCRIPT_DIR/xpanel" "$BIN_PATH"
    return
  fi
  # 2) build from source
  if [[ "$FROM_SOURCE" -eq 1 ]]; then
    build_from_source
    return
  fi
  # 3) download release tarball
  download_release
}

build_from_source() {
  local src="$SCRIPT_DIR/.."
  if [[ ! -f "$src/go.mod" ]]; then
    command -v git >/dev/null || die "git required for --from-source"
    src="$(mktemp -d)/XPanel-Go"
    echo ">> cloning $REPO"
    git clone --depth 1 "https://github.com/$REPO.git" "$src" \
      || die "clone failed (no network / no source)"
    git clone --depth 1 "https://github.com/MevYu/XPanel-Web.git" \
      "$(dirname "$src")/XPanel-Web" || die "frontend clone failed"
  fi
  command -v go >/dev/null || die "go toolchain required for --from-source"
  command -v npm >/dev/null || die "npm required for --from-source"
  echo ">> building from source at $src"
  ( cd "$src" && VERSION="$VERSION" bash scripts/build-release.sh )
  local tags=""; [[ "$WITH_FLEET" -eq 1 ]] && tags="-tags fleet"
  install -m 0755 "$src/release/xpanel${SUFFIX}-${VERSION}-linux-${ARCH}" "$BIN_PATH"
}

download_release() {
  command -v curl >/dev/null || die "curl required to download release"
  local tgz="xpanel${SUFFIX}-${VERSION}-linux-${ARCH}.tar.gz"
  local url="https://github.com/$REPO/releases/download/v${VERSION}/${tgz}"
  local tmp; tmp="$(mktemp -d)"
  echo ">> downloading $url"
  curl -fsSL "$url" -o "$tmp/$tgz" \
    || die "download failed; retry with --from-source or stage the binary"
  tar -C "$tmp" -xzf "$tmp/$tgz"
  install -m 0755 "$tmp/xpanel" "$BIN_PATH"
}

install_unit() {
  if [[ -f "$SCRIPT_DIR/xpanel.service" ]]; then
    install -m 0644 "$SCRIPT_DIR/xpanel.service" "$UNIT_PATH"
  else
    die "xpanel.service not found next to installer"
  fi
}

main() {
  echo ">> XPanel installer (arch=$ARCH, version=$VERSION, fleet=$WITH_FLEET)"
  install_binary
  echo ">> creating data dir $DATA_DIR"
  mkdir -p "$DATA_DIR"
  chmod 0700 "$DATA_DIR"

  install_unit
  systemctl daemon-reload
  echo ">> enabling + starting xpanel.service"
  systemctl enable --now xpanel.service

  # First start bootstraps the admin user and prints the password once; grab it
  # from the journal before it scrolls away.
  sleep 2
  echo
  echo "========================================================"
  local log
  log="$(journalctl -u xpanel.service --no-pager -n 100 2>/dev/null || true)"
  local addr pass
  addr="$(echo "$log" | grep -oE 'http://[0-9.]+:[0-9]+' | tail -n1 || true)"
  pass="$(echo "$log" | awk -F': ' '/^密码: /{print $2}' | tail -n1 || true)"

  if [[ -n "$pass" ]]; then
    echo "XPanel is running."
    echo "  URL:      ${addr:-http://127.0.0.1:8765}"
    echo "  Username: admin"
    echo "  Password: $pass"
    echo
    echo "  Change this password immediately after first login."
  else
    echo "XPanel started, but the first-run password was not found in the log."
    echo "Inspect it with:  journalctl -u xpanel.service | grep 密码"
  fi
  echo
  echo "NOTE: XPanel binds 127.0.0.1:8765 by default. Put it behind a TLS"
  echo "reverse proxy, or edit ${DATA_DIR}/config.json to change 'addr'."
  echo "========================================================"
}

main
