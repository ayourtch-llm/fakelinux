#!/usr/bin/env bash
# Hypothesis-4 partition test for the GCM-decrypt async-signal corruption.
#
# Background
# ----------
# Under fakelinux (Linux-syscall emulator on macOS ARM64), the canonical repro
# tests/repro/gcm_signal_corruption.py produces ~3% corrupted AES-GCM decrypts
# when aggressive SIGALRMs land during the decrypt loop. Six in-tree probes
# (KS_PROBE, RK_PROBE, FWD_REG_PROBE, REG_PROBE, RESUME_PROBE, ALTSTACK A/B)
# all came back byte-perfect — every register and every memory region
# fakelinux mediates between the SIGALRM interrupt and the openssl resume is
# preserved bit-for-bit. The bug exists but is invisible to any state probe.
#
# Native ARM64 macOS python (using macOS's openssl) shows 0/8000 corruption
# at matched signal density (~3.7 signals/decrypt, ~5x fakelinux's density),
# so the bug is NOT a generic openssl-async-signal-density problem on the
# macOS build. The ONE openssl-side hypothesis still standing is that the
# guest LINUX openssl binary itself misbehaves under aggressive SIGALRM in a
# way the macOS openssl doesn't — testable only by running the SAME Linux
# binary on a native Linux ARM64 box.
#
# What this script does
# ---------------------
# Sets up an isolated venv with `cryptography` (which transitively pulls
# Linux's openssl), then runs the canonical repro at two intensities:
#   1) The standard 8000 iters / 1970 B / 200 us SIGALRM that fakelinux fails.
#   2) Matched-density 8000 iters / 4020 B / 5 us SIGALRM to mirror what was
#      run on native macOS (29,817 ticks → ~3.7 signals/decrypt, the upper
#      end of what fakelinux sees).
#
# Interpretation
# --------------
#   - bad = 0 on both runs        → fakelinux IS the culprit; the Linux openssl
#                                   binary is signal-safe natively. Continue
#                                   debugging fakelinux's interaction with macOS
#                                   signal delivery (probes 1–6 already clean,
#                                   so the next angle is microarchitectural).
#   - bad > 0 on either run       → the bug is in the openssl Linux binary's
#                                   async-signal handling, not fakelinux. The
#                                   fakelinux investigation can be parked; the
#                                   fix belongs in openssl or its build flags.
#
# Requirements
# ------------
#   - aarch64 Linux (uname -m == aarch64)
#   - python3 (>= 3.8) and python3-venv
#   - pip-installable `cryptography` package (pulls openssl)
#
# Usage
# -----
#   ./run_linux_arm64.sh                # both runs, default settings
#   KEEP_VENV=1 ./run_linux_arm64.sh    # don't delete the venv on exit

set -eu

here="$(cd "$(dirname "$0")" && pwd)"
repro="${here}/gcm_signal_corruption.py"

if [ ! -f "${repro}" ]; then
    echo "ERROR: ${repro} not found" >&2
    exit 2
fi

arch="$(uname -m)"
if [ "${arch}" != "aarch64" ] && [ "${arch}" != "arm64" ]; then
    echo "WARNING: this script is intended for ARM64 Linux; you are on '${arch}'." >&2
    echo "The repro will still run, but the result does not address hypothesis-4." >&2
fi

os="$(uname -s)"
if [ "${os}" != "Linux" ]; then
    echo "WARNING: this script is intended for Linux; you are on '${os}'." >&2
    echo "The point is to test the LINUX openssl binary, not the host's." >&2
fi

venv_dir="$(mktemp -d)"
trap '[ "${KEEP_VENV:-0}" = "1" ] || rm -rf "${venv_dir}"' EXIT

echo "==> Creating venv at ${venv_dir}"
python3 -m venv "${venv_dir}"
# shellcheck disable=SC1091
. "${venv_dir}/bin/activate"
pip install --quiet --upgrade pip
pip install --quiet cryptography

echo
echo "==> openssl version reported by cryptography:"
python3 -c "from cryptography.hazmat.backends.openssl.backend import backend; print(backend.openssl_version_text())"
echo

echo "==> Run 1: canonical (8000 iters, 1970 B, 200 us SIGALRM)"
echo "    fakelinux baseline: bad ≈ 270–300 / 8000"
python3 "${repro}" 8000 1970 0.0002 || true
echo

echo "==> Run 2: matched-density (8000 iters, 4020 B, 5 us SIGALRM)"
echo "    matches the native-macOS 0/8000 cut (~3.7 signals/decrypt)"
python3 "${repro}" 8000 4020 0.000005 || true
echo

echo "==> Interpretation:"
echo "    Both bad=0  -> Linux openssl is async-signal-safe; fakelinux is the culprit."
echo "    Either bad>0 -> openssl Linux binary has the async-signal bug; not fakelinux."
echo
echo "    Please paste the TOTAL lines from both runs back to the investigation."
