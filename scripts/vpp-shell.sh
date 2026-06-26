#!/usr/bin/env bash
#
# vpp-shell.sh — drop into a shell inside the VPP build environment: the guest
# Ubuntu rootfs (under fakelinux), starting in the VPP source tree (/root/vpp)
# with the full toolchain that build-vpp.sh installed. From here you can
# `make build`, `git`, run tests, etc.
#
#   scripts/vpp-shell.sh              # interactive shell in /root/vpp
#   scripts/vpp-shell.sh make build   # run a single command in /root/vpp, then exit
#
# Env: ROOTFS (default roots/ubuntu).
#
# Thin wrapper over rootfs-shell.sh with START_DIR pinned to the VPP tree.
#
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec env START_DIR="${START_DIR:-/root/vpp}" "$SCRIPT_DIR/rootfs-shell.sh" "$@"
