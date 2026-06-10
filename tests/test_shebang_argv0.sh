#!/bin/bash
# Shebang argv[0] semantics: Linux passes the shebang interpreter path
# VERBATIM as argv[0] — it must NOT be symlink-resolved. CPython relies on
# this to find pyvenv.cfg next to a venv's bin/python3 symlink; resolving
# it to /usr/bin/python3.12 breaks venv detection (PEP 668 error during
# VPP's dpdk meson-venv pip install).
#
# Usage: tests/test_shebang_argv0.sh [path-to-ubuntu-rootfs]
set -e
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ROOTFS="${1:-$PROJECT_DIR/ubuntu-rootfs}"
FAKELINUX="$PROJECT_DIR/target/release/fakelinux"

[ -x "$FAKELINUX" ] || { echo "SKIP: build target/release/fakelinux first"; exit 0; }
[ -d "$ROOTFS/usr/bin" ] || { echo "SKIP: no rootfs at $ROOTFS"; exit 0; }

out=$(FAKELINUX_ROOT="$ROOTFS" "$FAKELINUX" --container "$ROOTFS/bin/bash" -c '
  rm -rf /tmp/argv0test && python3 -m venv --without-pip /tmp/argv0test
  printf "#!/tmp/argv0test/bin/python3\nimport sys\nprint(\"PREFIX=\" + sys.prefix)\n" > /tmp/argv0test/runme
  chmod +x /tmp/argv0test/runme
  /tmp/argv0test/runme
' 2>&1)

echo "$out" | grep -v '^fakelinux:' || true
if echo "$out" | grep -q '^PREFIX=/tmp/argv0test$'; then
    echo "PASS test_shebang_argv0"
else
    echo "FAIL test_shebang_argv0: expected PREFIX=/tmp/argv0test"
    exit 1
fi
