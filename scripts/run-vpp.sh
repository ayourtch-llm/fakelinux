#!/usr/bin/env bash
#
# run-vpp.sh — run the VPP built by build-vpp.sh, or smoke-test that it works.
#
#   scripts/run-vpp.sh            # run VPP with its interactive CLI (needs a TTY)
#   scripts/run-vpp.sh test       # automated smoke test: boot VPP, drive it via
#                                 # vppctl over cli.sock, check it responds
#   scripts/run-vpp.sh vppctl ... # run a single vppctl command against a running VPP
#
# Env: ROOTFS (default roots/ubuntu).
#
# VPP's interactive CLI needs a real terminal, so automated testing instead runs
# VPP as a service (cli-listen on a Unix socket) and talks to it with vppctl from
# a separate process — which also exercises fakelinux's AF_UNIX cross-process
# support.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
cd "$REPO_DIR"
# shellcheck source=scripts/lib.sh
. "$SCRIPT_DIR/lib.sh"

ROOTFS="${ROOTFS:-roots/ubuntu}"
# Match casefold to the rootfs's filesystem (so files built under casefold are
# found at runtime). No-op on a case-sensitive volume.
fl_autodetect_casefold "$REPO_DIR/$ROOTFS"
FAKELINUX_BIN="target/release/fakelinux"
VPP_BINDIR="root/vpp/build-root/install-vpp_debug-native/vpp/bin"
VPP_REL="$VPP_BINDIR/vpp"
VPPCTL_REL="$VPP_BINDIR/vppctl"
CONF='unix { nodaemon cli-listen /run/vpp/cli.sock } plugins { plugin dpdk_plugin.so { disable } }'

note() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
denoise() { grep -avE 'fakelinux: (loading|x18|runtime|patched|interpreter|entry|container|HUGE|  frame)|^x[0-9a-f]+'; }

[ -x "$FAKELINUX_BIN" ] || die "fakelinux not built — run: cargo build --release"
[ -x "$ROOTFS/$VPP_REL" ] || die "VPP not built at $ROOTFS/$VPP_REL — run: scripts/build-vpp.sh"

# Run a guest binary (host path within ROOTFS) under fakelinux.
fl() {
  FAKELINUX_ROOT="$REPO_DIR/$ROOTFS" FAKELINUX_PAGESZ=16384 \
    "./$FAKELINUX_BIN" --container "$@"
}

reset_runtime() {
  find "$ROOTFS/dev/shm" -type f -delete 2>/dev/null || true
  rm -f "$ROOTFS/run/vpp/cli.sock"
  mkdir -p "$ROOTFS/run/vpp"
}

# vppctl against the running VPP service. `|| true` because grep/denoise returns
# non-zero when a command is silent on success (e.g. `set interface ...`), which
# would otherwise trip `set -e`.
vppctl() { fl "$ROOTFS/$VPPCTL_REL" -s /run/vpp/cli.sock "$@" 2>/dev/null | denoise || true; }

kill_vpp() { pkill -9 -f "$VPP_REL " 2>/dev/null || true; }

do_interactive() {
  reset_runtime
  note "starting VPP (interactive CLI; type 'quit' or Ctrl-D to exit)..."
  exec env FAKELINUX_ROOT="$REPO_DIR/$ROOTFS" FAKELINUX_PAGESZ=16384 \
    "./$FAKELINUX_BIN" --container "$ROOTFS/$VPP_REL" \
    'unix { nodaemon interactive cli-listen /run/vpp/cli.sock } plugins { plugin dpdk_plugin.so { disable } }'
}

do_test() {
  reset_runtime
  trap kill_vpp EXIT
  note "booting VPP as a service..."
  fl "$ROOTFS/$VPP_REL" "$CONF" > /tmp/vpp-svc.out 2>&1 &

  local i
  for i in $(seq 1 40); do
    [ -S "$ROOTFS/run/vpp/cli.sock" ] && break
    sleep 1
  done
  [ -S "$ROOTFS/run/vpp/cli.sock" ] || { tail -20 /tmp/vpp-svc.out | denoise; die "VPP did not open its CLI socket"; }
  note "CLI socket up; querying VPP..."

  local ver
  ver="$(vppctl show version)"
  echo "  $ver"
  echo "$ver" | grep -qiE 'vpp v[0-9]' || die "no version banner from VPP"

  # Exercise the dataplane: create an interface and give it an address.
  vppctl create loopback interface >/dev/null
  vppctl set interface ip address loop0 10.10.10.1/24 >/dev/null
  vppctl set interface state loop0 up >/dev/null
  local addr
  addr="$(vppctl show interface address)"
  echo "$addr" | sed 's/^/  /'
  echo "$addr" | grep -q '10.10.10.1/24' || die "interface address not configured — dataplane not responding"

  note "VPP smoke test PASSED (version + interface config verified)."
}

case "${1:-run}" in
  run)    do_interactive ;;
  test)   do_test ;;
  vppctl) shift; vppctl "$@" ;;
  *) die "usage: scripts/run-vpp.sh {run|test|vppctl <cmd>}" ;;
esac
