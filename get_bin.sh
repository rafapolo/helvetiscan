#!/usr/bin/env bash
set -euo pipefail

REPO="rafapolo/helvetiscan"
BIN="helvetiscan"

# Detect platform
OS="$(uname -s)"
ARCH="$(uname -m)"

case "${OS}-${ARCH}" in
  Darwin-arm64)  TARGET="aarch64-apple-darwin" ;;
  Darwin-x86_64) TARGET="x86_64-apple-darwin" ;;
  Linux-x86_64)  TARGET="x86_64-unknown-linux-gnu" ;;
  *)
    echo "Unsupported platform: ${OS}-${ARCH}" >&2
    exit 1
    ;;
esac

ARTIFACT="${BIN}-${TARGET}"

# Resolve tag: use first arg or latest release
TAG="${1:-}"
if [[ -z "$TAG" ]]; then
  TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
fi

if [[ -z "$TAG" ]]; then
  echo "Could not determine latest release tag." >&2
  exit 1
fi

URL="https://github.com/${REPO}/releases/download/${TAG}/${ARTIFACT}"

echo "Downloading ${BIN} ${TAG} for ${TARGET}..."
curl -fSL --progress-bar "$URL" -o "${BIN}"
chmod +x "${BIN}"

echo "Done. Binary saved as: $(pwd)/${BIN}"
echo "Run: ./${BIN} --help"
