#!/usr/bin/env bash
set -euo pipefail

IMAGE="helvetiscan-musl-builder"
TARGET="x86_64-unknown-linux-musl"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Building static Linux binary (musl)"
echo "    Image  : $IMAGE"
echo "    Target : $TARGET"
echo ""

if ! docker image inspect "$IMAGE" &>/dev/null; then
  echo "--- [1/2] Building builder image (first time only)..."
  docker build --platform linux/amd64 -t "$IMAGE" -f "$SCRIPT_DIR/Dockerfile.musl" "$SCRIPT_DIR"
  echo ""
else
  echo "--- [1/2] Builder image already exists, skipping."
  echo ""
fi

echo "--- [2/2] Building release binary..."
docker run --rm \
  --platform linux/amd64 \
  -v "$(pwd)":/app \
  -w /app \
  "$IMAGE" \
  sh -c "
    set -e
    cargo build --release --target $TARGET
    echo ''
    echo 'Done. Binary written to target/$TARGET/release/'
    ls -lh target/$TARGET/release/ | grep -v '\.d$'
  "

echo ""
echo "==> Build complete."
scp target/x86_64-unknown-linux-musl/release/helvetiscan kosmos:/home/polo/apps/helvetiscan
