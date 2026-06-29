#!/usr/bin/env bash
#
# Multi-DSO load smoke test: run `apt-get update` in the guest under fakelinux.
#
# WHY: narrow crypto repros (tests/repro/gcm_signal_corruption.py) and even the
# FORCE_PHDR experiment can pass while a real regression in fakelinux's runtime
# code patching / DSO range extraction corrupts an unrelated guest binary's
# .interp/.dynstr so it FAILS TO LOAD (the `ld-linux-aa` class of bug). apt-get
# loads a broad stack of shared objects (libapt-pkg, libsystemd, gnutls, …) and
# forks helper binaries (http method, gpgv, …), so "apt-get ran at all" is a
# strong signal that runtime DSO loading + patching is intact.
#
# PASS  = apt-get loaded and executed (produced normal apt output).
# FAIL  = a load/crash signature (fakelinux's fault).
# SKIP  = no guest rootfs present.
#
# Network/mirror failures (Hash Sum mismatch, Failed to fetch) do NOT fail the
# test — they are upstream, not a fakelinux regression.
#
# Usage: tests/smoke/apt-get-update.sh
set -u

cd "$(dirname "$0")/../.." || { echo "FAIL: cannot find repo root"; exit 1; }

ROOTFS=roots/ubuntu
if [ ! -d "$ROOTFS" ]; then
    echo "SKIP: no guest rootfs at $ROOTFS"
    exit 0
fi
if [ ! -x scripts/vpp-shell.sh ]; then
    echo "SKIP: scripts/vpp-shell.sh not found/executable"
    exit 0
fi

pkill -9 -f fakelinux 2>/dev/null
sleep 1

out=$(timeout 300 scripts/vpp-shell.sh 'apt-get update' 2>&1)
rc=$?

# Load/crash signatures = a fakelinux regression in DSO loading or code patching.
load_fail_re='error while loading shared libraries|cannot open shared object|Segmentation fault|Illegal instruction|core dumped|fakelinux: .*(SIGSEGV|SIGBUS|panic|RESTORE-GARBAGE|invalid sigframe)'
if echo "$out" | grep -qiE "$load_fail_re"; then
    echo "FAIL: apt-get failed to load/run under fakelinux (regression):"
    echo "$out" | grep -iE "$load_fail_re" | head -5 | sed 's/^/    /'
    exit 1
fi

# Sanity: apt-get must have actually executed and produced its normal output.
ran_re='Reading package lists|Reading state information|^Get:|^Hit:|^Ign:|^Err:|^Fetched|All packages are up to date'
if echo "$out" | grep -qiE "$ran_re"; then
    echo "PASS: apt-get loaded and ran (multi-DSO dynamic linking + patching OK)."
    echo "$out" | grep -iE 'Reading package lists|^Fetched|All packages are up to date' | tail -2 | sed 's/^/    /'
    exit 0
fi

echo "FAIL: apt-get produced no recognizable output (rc=$rc) — did it run?"
echo "$out" | grep -vE 'fakelinux: (__TEXT bounds|altstack|runtime patch)' | tail -12 | sed 's/^/    /'
exit 1
