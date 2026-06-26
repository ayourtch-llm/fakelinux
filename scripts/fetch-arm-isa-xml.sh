#!/usr/bin/env bash
#
# fetch-arm-isa-xml.sh — populate data/encoding/ with ARM's A64 ISA XML.
#
# The instruction decoder is generated at build time from ARM's machine-readable
# A64 ISA specification. Those XML files are ARM-copyrighted and are NOT vendored
# in this repository (see data/encoding/README.md). This script fetches them.
#
# ARM publishes the spec on its "exploration tools" page. ARM rotates the CDN
# paths between releases, so this script supports several modes:
#
#   0. With no argument, it queries ARM's download manifest (the layout-service
#      JSON behind the A-Profile page) and downloads the newest A64 ISA XML.
#   1. Download from an explicit URL ($ARM_ISA_XML_URL or arg 1).
#   2. Extract a tarball you already downloaded (pass its path as arg 1).
#   3. Copy from an already-extracted directory (pass the dir as arg 1).
#
# Usage:
#   scripts/fetch-arm-isa-xml.sh                       # auto: resolve + download
#   scripts/fetch-arm-isa-xml.sh <url>                 # download from a URL
#   scripts/fetch-arm-isa-xml.sh ~/Downloads/ISA_A64_xml_A_profile-2025-06.tar.gz
#   scripts/fetch-arm-isa-xml.sh ~/some/extracted/dir
#   ARM_ISA_XML_URL=<url> scripts/fetch-arm-isa-xml.sh
#   FORCE=1 scripts/fetch-arm-isa-xml.sh               # overwrite existing files
#
set -euo pipefail

# --- locate the repo and the target dir ----------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
DEST="$REPO_DIR/data/encoding"

note() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# ARM's download links aren't static — they live in the Sitecore layout-service
# JSON behind the A-Profile architecture page. When you don't supply a source,
# this script queries that manifest and picks the newest A64 ISA XML tarball.
# All of these can be overridden if ARM changes them.
ARM_LAYOUT_URL="${ARM_LAYOUT_URL:-https://developer.arm.com/sitecore/api/layout/render/jss}"
ARM_LAYOUT_ITEM="${ARM_LAYOUT_ITEM:-/Architectures/A-Profile Architecture}"
ARM_LAYOUT_APIKEY="${ARM_LAYOUT_APIKEY:-360D01BB-34B8-46BC-B5BD-9FFFD7D289BF}"
ARM_LAYOUT_SITE="${ARM_LAYOUT_SITE:-Developer2-0}"

# Query ARM's manifest and echo the newest plain A64 ISA XML tarball URL.
# "Plain" = exclude the _FAT / _96 / _ASL0 variants and the AArch32/SysReg/
# AARCHMRS packages; build.rs wants the per-instruction A64 ISA XML.
resolve_arm_url() {
  command -v curl >/dev/null || return 1
  curl -fsSL --max-time 30 -G "$ARM_LAYOUT_URL" \
      --data-urlencode "item=$ARM_LAYOUT_ITEM" \
      --data-urlencode "sc_apikey=$ARM_LAYOUT_APIKEY" \
      --data-urlencode "sc_site=$ARM_LAYOUT_SITE" \
      --data-urlencode "sc_lang=en" 2>/dev/null \
    | grep -oE 'https?://[^"\\ ]*ISA_A64_xml_A_profile-[0-9]{4}-[0-9]{2}\.tar\.gz' \
    | sort -u | tail -1
}

print_howto() {
  cat >&2 <<'EOF'
Could not get the ARM A64 ISA XML automatically. It is not bundled (ARM-copyrighted).

Get it from ARM, then point this script at it:

  1. Open ARM's A-Profile architecture downloads:
       https://developer.arm.com/Architectures/A-Profile%20Architecture
     (or https://developer.arm.com/downloads/-/exploration-tools)
  2. Under Downloads, find "A64 ISA XML for A-profile architecture"
     (a file like ISA_A64_xml_A_profile-YYYY-MM.tar.gz). Right-click it and
     "Copy link", or just download it.
  3. Re-run this script with that link, the downloaded file, or its extracted dir:

       scripts/fetch-arm-isa-xml.sh '<copied-link-url>'
       scripts/fetch-arm-isa-xml.sh ~/Downloads/ISA_A64_xml_A_profile-2025-06.tar.gz
       scripts/fetch-arm-isa-xml.sh ~/Downloads/ISA_A64_xml_A_profile-2025-06/

     or set it once in the environment:

       ARM_ISA_XML_URL='<copied-link-url>' scripts/fetch-arm-isa-xml.sh

NOTE: you want the A64 *ISA XML* package (per-instruction encodings,
encodingindex.xml), NOT the "AARCHMRS Features.json" feature model — build.rs
parses the XML.
EOF
}

ARG="${1:-${ARM_ISA_XML_URL:-}}"
if [ -z "$ARG" ]; then
  note "No source given — querying ARM's download manifest for the latest A64 ISA XML…"
  if ARG="$(resolve_arm_url)" && [ -n "$ARG" ]; then
    note "Resolved: $ARG"
  else
    print_howto
    exit 1
  fi
fi
SRC="$ARG"

command -v tar >/dev/null  || die "tar not found"

# --- guard against clobbering an existing population ---------------------------
existing="$(find "$DEST" -maxdepth 1 -name '*.xml' 2>/dev/null | wc -l | tr -d ' ')"
if [ "$existing" != "0" ] && [ -z "${FORCE:-}" ]; then
  note "data/encoding/ already has $existing XML files. Set FORCE=1 to re-populate."
  exit 0
fi

# --- obtain a directory of extracted spec files --------------------------------
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
SRC_DIR=""

if [ -d "$SRC" ]; then
  note "Using already-extracted directory: $SRC"
  SRC_DIR="$SRC"
else
  TARBALL=""
  if [ -f "$SRC" ]; then
    note "Using local tarball: $SRC"
    TARBALL="$SRC"
  else
    command -v curl >/dev/null || die "curl not found (needed to download)"
    note "Downloading ARM A64 ISA XML from:"
    note "  $SRC"
    TARBALL="$WORK/isa.tar.gz"
    if ! curl -fSL --retry 3 -o "$TARBALL" "$SRC"; then
      warn "Download failed. ARM gates these files and rotates the URL per release."
      cat >&2 <<EOF

To install the spec manually:
  1. Open https://developer.arm.com/downloads/-/exploration-tools
  2. Download the "A64 ISA XML for A-profile architecture" tarball.
  3. Re-run this script pointing at it, e.g.:
       scripts/fetch-arm-isa-xml.sh ~/Downloads/ISA_A64_xml_A_profile-*.tar.gz
     (or pass the extracted directory instead of the tarball).

You can also set a known-good URL:
       ARM_ISA_XML_URL=<url> scripts/fetch-arm-isa-xml.sh
EOF
      exit 1
    fi
  fi
  note "Extracting…"
  tar -xf "$TARBALL" -C "$WORK"
  SRC_DIR="$WORK"
fi

# --- find the XML and copy it in ------------------------------------------------
# The tarball/dir may nest the files under a release subdirectory; search for the
# instruction XML wherever it lives.
xml_count="$(find "$SRC_DIR" -name '*.xml' | wc -l | tr -d ' ')"
[ "$xml_count" != "0" ] || die "no .xml files found under $SRC_DIR — is this the A64 ISA XML release?"

# Sanity-check that this looks like the A64 ISA spec build.rs expects.
if ! find "$SRC_DIR" -name 'encodingindex.xml' | grep -q . \
   && ! grep -rlq "<instructionsection" "$SRC_DIR" 2>/dev/null; then
  warn "Couldn't find encodingindex.xml or <instructionsection> — this may be the wrong package."
fi

mkdir -p "$DEST"
note "Copying $xml_count XML files (and any .dtd schemas) into data/encoding/ …"
find "$SRC_DIR" \( -name '*.xml' -o -name '*.dtd' \) -exec cp -f {} "$DEST"/ \;

final="$(find "$DEST" -maxdepth 1 -name '*.xml' | wc -l | tr -d ' ')"
note "Done. data/encoding/ now has $final XML files."
note "Build the decoder with:  cargo build --release"
