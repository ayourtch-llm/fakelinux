#!/bin/bash
# Container cwd semantics: when fakelinux --container is launched from a
# host directory OUTSIDE the rootfs, the guest must NOT inherit the host
# cwd (it doesn't exist in the guest's world — dpkg-preconfigure died with
# "cannot stat initial working directory for /Users/...").  A container
# starts at /.  A host cwd INSIDE the rootfs is preserved (guest-relative).
#
# Usage: tests/test_container_cwd.sh [path-to-rootfs]
set -e
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ROOTFS="${1:-$PROJECT_DIR/roots/ubuntu}"
FAKELINUX="$PROJECT_DIR/target/release/fakelinux"

[ -x "$FAKELINUX" ] || { echo "SKIP: build target/release/fakelinux first"; exit 0; }
[ -d "$ROOTFS/usr/bin" ] || { echo "SKIP: no rootfs at $ROOTFS"; exit 0; }

fail=0

# 1) host cwd outside the rootfs → guest pwd must be /
out=$(cd /tmp && FAKELINUX_ROOT="$ROOTFS" "$FAKELINUX" --container "$ROOTFS/bin/bash" -c 'pwd' 2>/dev/null)
if [ "$out" = "/" ]; then
  echo "PASS: outside-rootfs host cwd -> guest sees /"
else
  echo "FAIL: outside-rootfs host cwd -> guest pwd = '$out' (want /)"
  fail=1
fi

# 2) host cwd inside the rootfs → guest pwd is the guest-relative path
out=$(cd "$ROOTFS/var/log" && FAKELINUX_ROOT="$ROOTFS" "$FAKELINUX" --container "$ROOTFS/bin/bash" -c 'pwd' 2>/dev/null)
if [ "$out" = "/var/log" ]; then
  echo "PASS: inside-rootfs host cwd preserved as /var/log"
else
  echo "FAIL: inside-rootfs host cwd -> guest pwd = '$out' (want /var/log)"
  fail=1
fi

exit $fail
