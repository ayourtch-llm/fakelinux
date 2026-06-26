#!/usr/bin/env bash
#
# make-case-sensitive-volume.sh — mount a case-sensitive APFS volume at a path.
#
# macOS's default APFS volume is CASE-INSENSITIVE. Some Linux packages ship files
# whose names differ only in case (e.g. the kernel headers in linux-libc-dev:
# netfilter/xt_CONNMARK.h vs xt_connmark.h). Unpacking those into a guest root
# filesystem on a case-insensitive volume fails ("unable to install new version
# of ..."). Building anything that pulls in build-essential / kernel headers
# (such as VPP) therefore needs a case-sensitive filesystem.
#
# This creates a case-sensitive APFS *sparse* disk image (grows on demand, so a
# large nominal size costs almost nothing until used) and attaches it at the
# given mountpoint. It is idempotent: if the mountpoint is already a
# case-sensitive volume, it does nothing.
#
# Usage:
#   scripts/make-case-sensitive-volume.sh [mountpoint] [size] [image-path]
#     mountpoint   default: <repo>/roots-cs
#     size         default: 40g  (sparse — only real usage is allocated)
#     image-path   default: ~/fakelinux-roots.sparseimage
#
# To detach later:  hdiutil detach <mountpoint>
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

MNT="${1:-$REPO_DIR/roots-cs}"
SIZE="${2:-40g}"
IMG="${3:-$HOME/fakelinux-roots.sparseimage}"

note() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# Is $1 a directory on a case-sensitive filesystem?
is_case_sensitive() {
  [ -d "$1" ] || return 1
  local t; t="$(mktemp -d "$1/.cstest.XXXXXX")" || return 1
  : > "$t/x.tst"
  local n=1; [ -e "$t/X.TST" ] || n=2   # if X.TST is absent, the names are distinct
  rm -rf "$t"
  [ "$n" = 2 ]
}

if is_case_sensitive "$MNT"; then
  note "$MNT is already case-sensitive — nothing to do."
  exit 0
fi

mkdir -p "$MNT"
# Empty, non-case-sensitive dir at the mountpoint is fine (we mount over it).
if [ -n "$(ls -A "$MNT" 2>/dev/null)" ]; then
  die "$MNT is non-empty and not a case-sensitive mount. Pick an empty mountpoint."
fi

if [ ! -e "$IMG" ]; then
  note "creating case-sensitive APFS sparse image at $IMG ($SIZE nominal, sparse)..."
  hdiutil create -size "$SIZE" -type SPARSE -fs "Case-sensitive APFS" \
    -volname fakelinux-roots "$IMG" >/dev/null
fi

note "attaching $IMG at $MNT..."
hdiutil attach "$IMG" -mountpoint "$MNT" -nobrowse >/dev/null

is_case_sensitive "$MNT" || die "mounted volume is not case-sensitive — unexpected."
note "ready: case-sensitive volume mounted at $MNT"
