#!/usr/bin/env bash
# Build XPanel release artifacts: embed the frontend, cross-compile static
# binaries (linux/amd64, linux/arm64) with and without the fleet feature, and
# package each as a .tar.gz alongside install.sh + systemd unit + LICENSE.
set -euo pipefail

VERSION="${VERSION:-0.0.1}"
GO_REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB_REPO_DIR="${WEB_REPO_DIR:-$(cd "$GO_REPO_DIR/.." && pwd)/XPanel-Web}"
DIST_SRC="$WEB_REPO_DIR/dist"
DIST_DST="$GO_REPO_DIR/web/dist"
RELEASE_DIR="$GO_REPO_DIR/release"

echo ">> XPanel release build (version=$VERSION)"

# --- 1. frontend ---------------------------------------------------------
if [[ "${SKIP_FRONTEND:-0}" != "1" ]]; then
  if [[ ! -d "$WEB_REPO_DIR" ]]; then
    echo "error: frontend repo not found at $WEB_REPO_DIR (set WEB_REPO_DIR)" >&2
    exit 1
  fi
  echo ">> building frontend in $WEB_REPO_DIR"
  ( cd "$WEB_REPO_DIR" && npm ci && npm run build )
fi

if [[ ! -f "$DIST_SRC/index.html" ]]; then
  echo "error: frontend build output missing at $DIST_SRC" >&2
  exit 1
fi

echo ">> copying frontend dist -> $DIST_DST"
rm -rf "$DIST_DST"
mkdir -p "$DIST_DST"
cp -R "$DIST_SRC"/. "$DIST_DST"/

# --- 2. backend cross-compile -------------------------------------------
rm -rf "$RELEASE_DIR"
mkdir -p "$RELEASE_DIR"

build_one() {
  local arch="$1" tags="$2" suffix="$3"
  local out="xpanel${suffix}-${VERSION}-linux-${arch}"
  echo ">> building $out (tags='${tags:-none}')"
  ( cd "$GO_REPO_DIR" && \
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
    go build ${tags:+-tags "$tags"} \
      -ldflags "-s -w" \
      -o "$RELEASE_DIR/$out" ./cmd/xpanel )
  package_one "$out" "$arch" "$suffix"
}

package_one() {
  local binname="$1" arch="$2" suffix="$3"
  local stage tgz
  stage="$(mktemp -d)"
  install -m 0755 "$RELEASE_DIR/$binname" "$stage/xpanel"
  install -m 0644 "$GO_REPO_DIR/LICENSE" "$stage/LICENSE"
  install -m 0644 "$GO_REPO_DIR/scripts/xpanel.service" "$stage/xpanel.service"
  install -m 0755 "$GO_REPO_DIR/scripts/install.sh" "$stage/install.sh"
  tgz="$RELEASE_DIR/xpanel${suffix}-${VERSION}-linux-${arch}.tar.gz"
  tar -C "$stage" -czf "$tgz" .
  rm -rf "$stage"
  echo "   packaged $tgz"
}

for arch in amd64 arm64; do
  build_one "$arch" "" ""            # default build (no fleet)
  build_one "$arch" "fleet" "-fleet" # fleet variant
done

echo ">> done. artifacts in $RELEASE_DIR:"
ls -1 "$RELEASE_DIR"
