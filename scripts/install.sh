#!/usr/bin/env bash
# Install ip-scan from the latest GitHub release. Detects platform /
# architecture and downloads the matching tarball/zip into the current
# directory. Verifies SHA256 against the bundled SHA256SUMS file.
#
# Usage:
#   ./scripts/install.sh                 # install into ./ip-scan-*
#   INSTALL_DIR=/opt ./scripts/install.sh
#   TAG=v0.1.0 ./scripts/install.sh
#
# No Rust toolchain or Docker is required.

set -euo pipefail

REPO="${REPO:-Dave-he/ip-scan}"
TAG="${TAG:-latest}"
INSTALL_DIR="${INSTALL_DIR:-$PWD}"

uname_s=$(uname -s 2>/dev/null || echo "unknown")
uname_m=$(uname -m 2>/dev/null || echo "unknown")

case "$uname_s-$uname_m" in
  Linux-x86_64) ASSET="ip-scan-linux-x86_64-musl.tar.gz" ;;
  Linux-aarch64) ASSET="ip-scan-linux-aarch64-musl.tar.gz" ;;
  Darwin-x86_64) ASSET="ip-scan-macos-x86_64.tar.gz" ;;
  Darwin-arm64) ASSET="ip-scan-macos-aarch64.tar.gz" ;;
  MINGW*|CYGWIN*|MSYS*-x86_64) ASSET="ip-scan-windows-x86_64.zip" ;;
  *) echo "Unsupported platform: $uname_s-$uname_m" >&2; exit 1 ;;
esac

if [ "$TAG" = "latest" ]; then
  API_URL="https://api.github.com/repos/${REPO}/releases/latest"
  TAG=$(curl -sSL "$API_URL" | python3 -c "import sys, json; print(json.load(sys.stdin)['tag_name'])" 2>/dev/null || echo "")
  if [ -z "$TAG" ]; then
    echo "Failed to determine latest tag. Set TAG=vX.Y.Z and retry." >&2
    exit 1
  fi
fi

BASE="https://github.com/${REPO}/releases/download/${TAG}"
WORK=$(mktemp -d -t ip-scan.XXXX)
trap "rm -rf '$WORK'" EXIT

echo "==> Downloading $ASSET (tag=$TAG)"
curl -sSL -o "$WORK/$ASSET" "$BASE/$ASSET"
curl -sSL -o "$WORK/SHA256SUMS" "$BASE/SHA256SUMS"

cd "$WORK"
EXPECTED=$(awk -v a="$ASSET" '$2 == a { print $1 }' SHA256SUMS || true)
if [ -n "$EXPECTED" ]; then
  ACTUAL=$(sha256sum "$ASSET" | awk '{print $1}')
  if [ "$ACTUAL" != "$EXPECTED" ]; then
    echo "Checksum mismatch: expected $EXPECTED got $ACTUAL" >&2
    exit 1
  fi
  echo "==> SHA256 verified"
fi

mkdir -p "$INSTALL_DIR"
if [[ "$ASSET" == *.tar.gz ]]; then
  tar xzf "$ASSET" -C "$INSTALL_DIR"
elif [[ "$ASSET" == *.zip ]]; then
  unzip -q "$ASSET" -d "$INSTALL_DIR"
fi

EXTRACT_DIR="${ASSET%.tar.gz}"
EXTRACT_DIR="${EXTRACT_DIR%.zip}"
BIN="$INSTALL_DIR/$EXTRACT_DIR/ip-scan"
[ -f "$BIN.exe" ] && BIN="$BIN.exe"
echo "==> Installed to $BIN"
echo "Run: $BIN --api --node-id <name> --node-label <label>"
