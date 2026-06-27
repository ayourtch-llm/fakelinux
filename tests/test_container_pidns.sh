#!/bin/bash
# Container PID-namespace consistency — the basis of shell job control.
#
# Bash job control sets the terminal's foreground process group to getpid() and
# reads it back via tcgetpgrp(); if getpid() and getpgid()/tcgetpgrp() report
# different virtual PIDs for the same process, bash bails with "no job control
# in this shell". Two bugs caused that:
#   1. When the container init re-execs (login shell `exec`ing the interactive
#      shell — same real pid), it must stay vpid 1. The old code marked it a
#      child, so getpid() returned the real pid while tcgetpgrp() still mapped it
#      to 1.  -> REEXEC_PID must be 1.
#   2. A fork child inherited the init's IS_INIT flag (copy-on-write), so it also
#      reported vpid 1, colliding with init ("child setpgid (1 to 1)").
#      -> a subshell's pid must NOT be 1.
#
# Usage: tests/test_container_pidns.sh [path-to-rootfs]
set -e
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ROOTFS="${1:-$PROJECT_DIR/roots/ubuntu}"
FAKELINUX="$PROJECT_DIR/target/release/fakelinux"

[ -x "$FAKELINUX" ] || { echo "SKIP: build target/release/fakelinux first"; exit 0; }
[ -d "$ROOTFS/usr/bin" ] || { echo "SKIP: no rootfs at $ROOTFS"; exit 0; }
[ -e "$ROOTFS/bin/bash" ] || { echo "SKIP: no /bin/bash in $ROOTFS"; exit 0; }

fail=0

# --- 1) re-exec'd init stays vpid 1 (getpid/getpgid consistency) -------------
cat > "$ROOTFS/tmp/_pidns_reexec.sh" <<'EOF'
echo "INIT_PID=$$"
exec /bin/sh -c 'echo "REEXEC_PID=$$"'
EOF
out=$(FAKELINUX_ROOT="$ROOTFS" "$FAKELINUX" --container "$ROOTFS/bin/sh" /tmp/_pidns_reexec.sh 2>/dev/null)
rm -f "$ROOTFS/tmp/_pidns_reexec.sh"
init_pid=$(printf '%s\n' "$out" | sed -n 's/^INIT_PID=//p')
reexec_pid=$(printf '%s\n' "$out" | sed -n 's/^REEXEC_PID=//p')
if [ "$init_pid" = "1" ] && [ "$reexec_pid" = "1" ]; then
  echo "PASS: container init and its re-exec are both vpid 1"
else
  echo "FAIL: init_pid='$init_pid' reexec_pid='$reexec_pid' (want both 1)"
  fail=1
fi

# --- 2) fork child is NOT vpid 1 (no collision with init) --------------------
cat > "$ROOTFS/tmp/_pidns_fork.sh" <<'EOF'
echo "INIT=$$"
( echo "CHILD=$BASHPID" )
EOF
out=$(FAKELINUX_ROOT="$ROOTFS" "$FAKELINUX" --container "$ROOTFS/bin/bash" /tmp/_pidns_fork.sh 2>/dev/null)
rm -f "$ROOTFS/tmp/_pidns_fork.sh"
init=$(printf '%s\n' "$out" | sed -n 's/^INIT=//p')
child=$(printf '%s\n' "$out" | sed -n 's/^CHILD=//p')
if [ "$init" = "1" ] && [ -n "$child" ] && [ "$child" != "1" ]; then
  echo "PASS: init is vpid 1, fork child ($child) is not"
else
  echo "FAIL: init='$init' child='$child' (want init=1, child!=1)"
  fail=1
fi

exit $fail
