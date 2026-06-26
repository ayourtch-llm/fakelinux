#!/bin/sh
# Clean up between VPP smoke-test runs: kill stray guests, wipe stale svm
# shm regions. Safe to run anytime (idempotent).
cd "$(dirname "$0")/.." || exit 1
pkill -9 -f "vpp/bin/vpp" 2>/dev/null
pkill -9 -f "fakelinux --container.*vpp" 2>/dev/null
rm -f roots/ubuntu/dev/shm/* 2>/dev/null
exit 0
