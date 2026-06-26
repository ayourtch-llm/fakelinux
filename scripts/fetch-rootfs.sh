#!/usr/bin/env bash
#
# fetch-rootfs.sh — download an aarch64 Linux root filesystem into roots/<name>.
#
# fakelinux runs Linux binaries against a guest root filesystem that you point
# FAKELINUX_ROOT at. This script populates one using the project's own Docker-less
# OCI image puller (src/bin/fakelinux-pull.rs), which fetches the linux/arm64
# variant of an image and extracts its layers — no Docker required.
#
# Usage:
#   scripts/fetch-rootfs.sh <name> [image-ref]
#
#   <name>       subdirectory under roots/ to create (e.g. ubuntu, alpine).
#   [image-ref]  OCI image to pull. Optional for known presets (see below);
#                required otherwise. Examples: ubuntu:24.04, alpine:latest,
#                debian:sid, python:3.12-slim, ghcr.io/owner/repo:tag.
#
# Presets (just `scripts/fetch-rootfs.sh <name>`):
#   ubuntu  -> ubuntu:24.04
#   debian  -> debian:sid
#   alpine  -> alpine:latest
#   python  -> python:3.12-slim
#
# Examples:
#   scripts/fetch-rootfs.sh ubuntu                 # ubuntu:24.04 -> roots/ubuntu
#   scripts/fetch-rootfs.sh alpine                 # alpine:latest -> roots/alpine
#   scripts/fetch-rootfs.sh noble ubuntu:24.04     # custom name + image
#   FORCE=1 scripts/fetch-rootfs.sh ubuntu         # overwrite an existing tree
#
# Then run something in it (pass the binary as a host path that includes the
# roots/<name> prefix — fakelinux strips it to derive the guest's view):
#   FAKELINUX_ROOT=roots/ubuntu ./target/release/fakelinux --container roots/ubuntu/bin/bash
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

note() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

NAME="${1:-}"
IMAGE="${2:-}"
[ -n "$NAME" ] || die "usage: scripts/fetch-rootfs.sh <name> [image-ref]  (e.g. ubuntu, alpine)"

# Resolve presets when no explicit image was given.
if [ -z "$IMAGE" ]; then
  case "$NAME" in
    ubuntu) IMAGE="ubuntu:24.04" ;;
    debian) IMAGE="debian:sid" ;;
    alpine) IMAGE="alpine:latest" ;;
    python) IMAGE="python:3.12-slim" ;;
    *) die "no preset for '$NAME' — pass an image ref, e.g. scripts/fetch-rootfs.sh $NAME some-image:tag" ;;
  esac
fi

ROOTS="${ROOTS_DIR:-roots}"
DEST="$REPO_DIR/$ROOTS/$NAME"
if [ -e "$DEST" ] && [ -z "${FORCE:-}" ]; then
  note "$ROOTS/$NAME already exists. Set FORCE=1 to re-download (it will be replaced)."
  exit 0
fi

# Build the puller if needed.
PULL="$REPO_DIR/target/release/fakelinux-pull"
if [ ! -x "$PULL" ]; then
  note "Building fakelinux-pull…"
  ( cd "$REPO_DIR" && cargo build --release --bin fakelinux-pull )
fi

# Guest trees often contain read-only dirs (e.g. a synthetic /proc with no write
# bit), which defeat a plain `rm -rf`. Always chmod first.
nuke() {
  if [ -e "$1" ]; then
    chmod -R u+rwX "$1" 2>/dev/null || true
    rm -rf "$1"
  fi
}

# Pull into a temp dir, then swap into place so a failed pull never leaves a
# half-populated roots/<name>.
TMP="$REPO_DIR/$ROOTS/.$NAME.partial.$$"
nuke "$TMP"
trap 'nuke "$TMP"' EXIT

note "Pulling $IMAGE (linux/arm64) into $ROOTS/$NAME …"
"$PULL" "$IMAGE" "$TMP"

nuke "$DEST"
mv "$TMP" "$DEST"
trap - EXIT

# OCI images ship without a resolver (Docker injects one at runtime) and, for
# Debian/Ubuntu, with an apt cache too small for the full index under fakelinux.
# Set sane defaults so the tree is usable out of the box (networking + apt).
if [ ! -s "$DEST/etc/resolv.conf" ] && [ -d "$DEST/etc" ]; then
  printf 'nameserver 8.8.8.8\nnameserver 1.1.1.1\n' > "$DEST/etc/resolv.conf"
  note "wrote a default /etc/resolv.conf"
fi
if [ -d "$DEST/etc/apt" ]; then
  mkdir -p "$DEST/etc/apt/apt.conf.d"
  cat > "$DEST/etc/apt/apt.conf.d/99fakelinux" <<'EOF'
APT::Cache-Start "536870912";
Acquire::Languages "none";
EOF
  note "wrote apt tuning (etc/apt/apt.conf.d/99fakelinux)"
fi

note "Done. $ROOTS/$NAME is ready."
note "Run it with:  FAKELINUX_ROOT=$ROOTS/$NAME ./target/release/fakelinux --container $ROOTS/$NAME/bin/sh"
