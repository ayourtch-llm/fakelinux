#!/usr/bin/env bash
#
# vpp-shell.sh — drop into a shell inside the VPP build environment.
#
# Opens an interactive bash inside the guest Ubuntu rootfs (under fakelinux),
# starting in the VPP source tree (/root/vpp) with the full toolchain that
# build-vpp.sh installed. From here you can `make build`, `git`, run tests, etc.
#
#   scripts/vpp-shell.sh              # interactive shell in /root/vpp
#   scripts/vpp-shell.sh make build   # run a single command in /root/vpp, then exit
#
# Env: ROOTFS (default roots-cs/ubuntu).
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
cd "$REPO_DIR"

ROOTFS="${ROOTFS:-roots-cs/ubuntu}"
FAKELINUX_BIN="target/release/fakelinux"

die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ -x "$FAKELINUX_BIN" ] || die "fakelinux not built — run: cargo build --release"
[ -d "$ROOTFS/usr/bin" ] || die "no rootfs at $ROOTFS — run: scripts/build-vpp.sh"

# Start in /root/vpp if it exists, else /root.
START_DIR='/root/vpp'
[ -d "$ROOTFS/root/vpp" ] || START_DIR='/root'

if [ "$#" -gt 0 ]; then
  # Run the given command in the VPP tree, non-interactively.
  CMD="cd $START_DIR 2>/dev/null; $*"
else
  # Interactive login shell rooted in the VPP tree (needs a TTY).
  CMD="cd $START_DIR 2>/dev/null; exec bash -i"
fi

exec env FAKELINUX_ROOT="$REPO_DIR/$ROOTFS" FAKELINUX_PAGESZ=16384 \
  "./$FAKELINUX_BIN" --container "$ROOTFS/usr/bin/bash" -lc "$CMD"
