#!/usr/bin/env bash
#
# rootfs-shell.sh — open an interactive shell inside a guest root filesystem
# under fakelinux (virtual PID 1, virtual root).
#
#   scripts/rootfs-shell.sh                 # bash/sh in roots/ubuntu
#   scripts/rootfs-shell.sh uname -a        # run a command in the rootfs, then exit
#   ROOTFS=roots/alpine scripts/rootfs-shell.sh    # a different rootfs
#
# Env:
#   ROOTFS     guest tree to enter  (default: roots/ubuntu)
#   START_DIR  initial directory    (default: /root if present, else /)
#
# Picks bash if the rootfs has it, otherwise sh. Case-fold is enabled
# automatically when the rootfs is on a case-insensitive volume.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
cd "$REPO_DIR"
# shellcheck source=scripts/lib.sh
. "$SCRIPT_DIR/lib.sh"

ROOTFS="${ROOTFS:-roots/ubuntu}"
FAKELINUX_BIN="target/release/fakelinux"

die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ -x "$FAKELINUX_BIN" ] || die "fakelinux not built — run: cargo build --release"
[ -d "$ROOTFS" ] || die "no rootfs at $ROOTFS — fetch one with: scripts/fetch-rootfs.sh ${ROOTFS##*/}"

# Match casefold to the rootfs's filesystem (so case-colliding files are found).
fl_autodetect_casefold "$REPO_DIR/$ROOTFS"

# Pick a shell that exists in the rootfs (bash preferred, sh as fallback).
# Use -e OR -L: a guest shell is often an absolute symlink (e.g. Alpine's
# /bin/sh -> /bin/busybox) that looks dangling from the host but resolves fine
# inside the rootfs.
SHELL_REL=""
for s in usr/bin/bash bin/bash usr/bin/sh bin/sh; do
  if [ -e "$ROOTFS/$s" ] || [ -L "$ROOTFS/$s" ]; then SHELL_REL="$s"; break; fi
done
[ -n "$SHELL_REL" ] || die "no bash/sh found in $ROOTFS"
SH_GUEST="/$SHELL_REL"   # guest-visible path of the shell

# Initial directory.
START_DIR="${START_DIR:-}"
if [ -z "$START_DIR" ]; then
  if [ -d "$ROOTFS/root" ]; then START_DIR=/root; else START_DIR=/; fi
fi

if [ "$#" -gt 0 ]; then
  CMD="cd $START_DIR 2>/dev/null; $*"                 # run the given command
else
  CMD="cd $START_DIR 2>/dev/null; exec $SH_GUEST -i"  # interactive (needs a TTY)
fi

exec env FAKELINUX_ROOT="$REPO_DIR/$ROOTFS" FAKELINUX_PAGESZ=16384 \
  "./$FAKELINUX_BIN" --container "$ROOTFS/$SHELL_REL" -lc "$CMD"
