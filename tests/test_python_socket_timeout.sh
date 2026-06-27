#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ROOTFS="${ROOTFS:-$PROJECT_DIR/roots/ubuntu}"
GUEST_SCRIPT="/tmp/fakelinux-test-python-socket-timeout.py"
HOST_SCRIPT="$ROOTFS$GUEST_SCRIPT"

if [ ! -x "$PROJECT_DIR/target/release/fakelinux" ]; then
  (cd "$PROJECT_DIR" && cargo build --release)
fi

if [ ! -x "$ROOTFS/usr/bin/python3" ] && [ ! -x "$ROOTFS/bin/python3" ]; then
  echo "SKIP python socket timeout (no python3 in $ROOTFS)"
  exit 0
fi

cp "$SCRIPT_DIR/test_python_socket_timeout.py" "$HOST_SCRIPT"
trap 'rm -f "$HOST_SCRIPT"' EXIT

cd "$PROJECT_DIR"
output="$(./scripts/vpp-shell.sh python3 "$GUEST_SCRIPT" 2>&1)"
printf '%s\n' "$output"

grep -q '^socket-timeout-ok$' <<<"$output"
