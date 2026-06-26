#!/usr/bin/env bash
# Shared helpers for the fakelinux example scripts. Source this file.

# Is directory $1 on a case-sensitive filesystem? If $1 doesn't exist yet, its
# parent is tested instead (the new dir inherits the parent's volume).
fl_is_case_sensitive() {
  local d="$1"
  while [ -n "$d" ] && [ ! -d "$d" ]; do d="$(dirname "$d")"; done
  [ -d "$d" ] || return 1
  local t
  t="$(mktemp -d "$d/.cstest.XXXXXX" 2>/dev/null)" || return 1
  : > "$t/x.tst"
  local sensitive=0
  [ -e "$t/X.TST" ] || sensitive=1   # if X.TST is absent, names are distinct
  rm -rf "$t"
  [ "$sensitive" = 1 ]
}

# Enable FAKELINUX_CASEFOLD automatically when the rootfs at $1 sits on a
# case-insensitive volume (macOS default), so case-only-colliding filenames
# coexist without a separate case-sensitive disk image. An explicit
# FAKELINUX_CASEFOLD in the environment is always respected.
fl_autodetect_casefold() {
  [ -z "${FAKELINUX_CASEFOLD:-}" ] || return 0
  if fl_is_case_sensitive "$1"; then
    return 0   # real case-sensitive FS — nothing to do
  fi
  export FAKELINUX_CASEFOLD=1
}
