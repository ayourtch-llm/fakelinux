#!/usr/bin/env bash
#
# build-vpp.sh — build and run VPP (the FD.io Vector Packet Processor) entirely
# inside fakelinux, from a stock Ubuntu guest root filesystem.
#
# This is the project's "big" end-to-end example: a fresh Ubuntu userland under
# fakelinux installs its own build dependencies with apt, clones VPP, compiles
# it with gcc, and runs the resulting binary — all as native aarch64 code on
# macOS, with only syscalls emulated.
#
# Usage:
#   scripts/build-vpp.sh all        # build, then verify it boots  (default)
#   scripts/build-vpp.sh build      # fetch rootfs (if needed), deps, clone, compile
#   scripts/build-vpp.sh verify     # boot VPP non-interactively, check it runs
#   scripts/build-vpp.sh run        # launch the built VPP (interactive CLI)
#   scripts/build-vpp.sh shell      # drop into a guest shell in the rootfs
#
# Fully scripted end to end: from nothing it creates a case-sensitive volume,
# pulls ubuntu:24.04, installs deps, clones+builds VPP, and verifies it runs.
#
# Tunables (environment):
#   ROOTFS     guest tree to use            (default: roots/ubuntu)
#   VPP_REPO   VPP git URL                  (default: https://github.com/FDio/vpp.git)
#   VPP_REF    branch/tag/commit to check out (default: master)
#   JOBS       parallel make jobs           (default: number of host CPUs)
#
# Notes:
#   * The build is long the first time. It is incremental and ccache-backed on
#     re-runs, so repeat builds are fast — that is what makes iterating viable.
#   * Output is tee'd to build-vpp.log; the guest writes a DONE_RC marker line
#     ("VPP_BUILD_DONE rc=N") so the real exit status survives detaching.
#   * To run unattended:  nohup scripts/build-vpp.sh build >build-vpp.log 2>&1 &
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
cd "$REPO_DIR"

# VPP's build pulls in Linux kernel headers (linux-libc-dev) whose filenames
# collide under macOS's default case-insensitive APFS, so the rootfs lives on a
# case-sensitive volume (roots-cs/) that this script sets up automatically.
ROOTFS="${ROOTFS:-roots-cs/ubuntu}"
VPP_REPO="${VPP_REPO:-https://github.com/FDio/vpp.git}"
VPP_REF="${VPP_REF:-master}"
JOBS="${JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 4)}"
FAKELINUX_BIN="target/release/fakelinux"

# VPP's install-vpp_debug-native output path (debug build).
VPP_BIN_REL="root/vpp/build-root/install-vpp_debug-native/vpp/bin/vpp"

note() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# Run a command line inside the guest (virtual PID 1, virtual root).
guest() {
  FAKELINUX_ROOT="$REPO_DIR/$ROOTFS" FAKELINUX_PAGESZ=16384 \
    "./$FAKELINUX_BIN" --container "$ROOTFS/usr/bin/bash" -lc "$1"
}

ensure_prereqs() {
  [ -x "$FAKELINUX_BIN" ] || { note "building fakelinux..."; cargo build --release; }

  # Ensure the volume that holds ROOTFS is case-sensitive (required for kernel
  # headers). If ROOTFS sits under a dedicated dir (e.g. roots-cs/), set up a
  # case-sensitive APFS image there; if it's already case-sensitive, this no-ops.
  local roots_dir vol_mount
  roots_dir="$(dirname "$ROOTFS")"          # e.g. roots-cs
  vol_mount="$REPO_DIR/$roots_dir"
  scripts/make-case-sensitive-volume.sh "$vol_mount"

  if [ ! -d "$ROOTFS/usr/bin" ]; then
    note "no rootfs at $ROOTFS — fetching ubuntu:24.04..."
    ROOTS_DIR="$roots_dir" scripts/fetch-rootfs.sh "$(basename "$ROOTFS")" ubuntu:24.04
  fi
}

# The actual build recipe, executed inside the guest. Idempotent: skips the
# clone if the tree is present, and relies on make/ccache for incremental builds.
write_inner_script() {
  cat > "$ROOTFS/root/build-vpp-inner.sh" <<INNER
#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive

# apt/dpkg occasionally hit a transient hiccup under emulation (e.g. a fork race
# in a postinst). Retry, healing partial state between attempts, so the long
# build doesn't abort on a flake.
apt_install() {
  local t
  for t in 1 2 3; do
    apt-get install -y --no-install-recommends "\$@" && return 0
    echo "### apt retry \$t (healing dpkg state)"
    dpkg --configure -a || true
    apt-get -f install -y || true
  done
  return 1
}

echo "### apt update"
apt-get update || apt-get update
echo "### base build tools"
apt_install git make sudo ca-certificates build-essential cmake ninja-build python3 python3-pip
dpkg --configure -a || true
cd /root
if [ ! -d vpp/.git ]; then
  echo "### cloning VPP ($VPP_REPO @ $VPP_REF)"
  git clone --branch "$VPP_REF" "$VPP_REPO" vpp
fi
cd vpp
# VPP derives its version from \`git describe\`, which needs tags AND the history
# back to the nearest tag. A shallow/tagless clone makes scripts/version empty,
# which breaks cmake (string(REPLACE) with too few args). Ensure full history+tags.
if [ -f "\$(git rev-parse --git-dir)/shallow" ]; then git fetch --unshallow || true; fi
git fetch --tags || true
echo "### make install-dep (VPP's apt dependency set)"
for t in 1 2 3; do make UNATTENDED=yes install-dep && break; echo "### install-dep retry \$t"; dpkg --configure -a || true; done
echo "### make build (debug); ccache-backed on re-runs"
make build
rc=\$?
echo "VPP_BUILD_DONE rc=\$rc"
exit \$rc
INNER
  chmod +x "$ROOTFS/root/build-vpp-inner.sh"
}

do_build() {
  ensure_prereqs
  write_inner_script
  note "building VPP inside $ROOTFS (this is long the first time; incremental after)"
  guest "/root/build-vpp-inner.sh" 2>&1 | tee build-vpp.log
  if grep -q 'VPP_BUILD_DONE rc=0' build-vpp.log; then
    note "VPP build SUCCEEDED."
  else
    die "VPP build did not finish cleanly — see build-vpp.log (look for 'VPP_BUILD_DONE rc=')."
  fi
  [ -x "$ROOTFS/$VPP_BIN_REL" ] || die "expected VPP binary missing: $ROOTFS/$VPP_BIN_REL"
  note "VPP binary: $ROOTFS/$VPP_BIN_REL"
}

# Running and verifying VPP live in run-vpp.sh (interactive CLI needs a TTY;
# the smoke test drives VPP via vppctl over cli.sock). Delegate to it.
do_run()    { ROOTFS="$ROOTFS" scripts/run-vpp.sh run; }
do_verify() { ROOTFS="$ROOTFS" scripts/run-vpp.sh test; }

case "${1:-all}" in
  build)  do_build ;;
  run)    do_run ;;
  verify) do_verify ;;
  all)    do_build; do_verify ;;
  shell)  ensure_prereqs; guest "${2:-bash}" ;;
  *) die "usage: scripts/build-vpp.sh {build|run|verify|all|shell}" ;;
esac
