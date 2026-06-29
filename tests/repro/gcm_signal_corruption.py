#!/usr/bin/env python3
"""Minimal reproducer for the fakelinux async-signal memory-corruption bug.

WHAT IT SHOWS
-------------
A long AES-GCM decrypt of a LARGE buffer, run *inside fakelinux* while async
signals (an aggressive SIGALRM) land during the decrypt, occasionally produces a
corrupt plaintext block. The corruption is a stray ~16-byte write of foreign,
time-varying data onto the decrypt OUTPUT buffer (the GCM tag usually still
verifies, proving the ciphertext input was intact and the write happened AFTER
decrypt). See docs/plans/2026-06-28-vpp-100pct-pass.md sections A.4.7-A.4.9.

This is NOT a crypto bug: OPENSSL_armcap=0 (pure-C openssl, no NEON/AES asm) also
corrupts. It is a fakelinux signal/trap-handling bug; AES-GCM is just a reliable
trigger (long CPU-bound run = wide async-signal window). It is single-threaded.

It is the SAME bug that fails the VPP `test_ipsec_*` suite, because that suite's
test harness decrypts both its expected and received packets with this same
scapy/openssl path.

HOW TO RUN (inside the guest, under fakelinux)
----------------------------------------------
    scripts/vpp-shell.sh \
      '/root/vpp/build-root/test/venv/bin/python3 /tmp/gcm_signal_corruption.py 8000 1970'

(roots/ubuntu/tmp/ on the host maps to /tmp/ inside the guest, so copy this file
there, or invoke it from wherever the guest can see it.)

Args: [iterations] [payload_size_bytes] [sigalrm_interval_seconds]
Defaults: 4000 iters, 1970-byte payload, 200us SIGALRM.
A baseline (pass interval 0 to disable SIGALRM) still corrupts ~1/285 large
decrypts because some async signal reaches the process anyway.

EXPECTED RESULT
---------------
  - Native Linux / native macOS python: 0 corrupt over any number of iterations.
  - Under fakelinux: a nonzero "bad" count (rate scales with payload size and
    signal frequency). Exit code 1 if any corruption is seen.

The buffer is a FIXED, reused bytearray decrypted into via update_into(), and its
base address is printed, so it can be used as a stable FAKELINUX_WATCH target to
catch the guest PC performing the stray store.
"""
import ctypes
import os
import signal
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = bytes(range(32))            # fixed AES-256 key
NONCE = bytes(range(12))          # fixed 96-bit GCM nonce
FILL = 0x58                       # known plaintext byte ('X')

_ticks = 0
def _on_alarm(signum, frame):
    global _ticks
    _ticks += 1

def buffer_address(buf: bytearray) -> int:
    return ctypes.addressof((ctypes.c_char * len(buf)).from_buffer(buf))

def main() -> int:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 4000
    psize = int(sys.argv[2]) if len(sys.argv) > 2 else 1970
    interval = float(sys.argv[3]) if len(sys.argv) > 3 else 0.0002  # 200us

    plaintext = bytes([FILL]) * psize

    # Encrypt once.
    enc = Cipher(algorithms.AES(KEY), modes.GCM(NONCE)).encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    tag = enc.tag

    # Fixed, reused output buffer (stable address for FAKELINUX_WATCH).
    out = bytearray(len(ct) + 16)
    addr = buffer_address(out)
    print("fakelinux gcm repro: out_buf=%#x len=%d psize=%d iters=%d interval=%gs"
          % (addr, len(out), psize, n, interval), flush=True)

    if interval > 0:
        signal.signal(signal.SIGALRM, _on_alarm)
        signal.setitimer(signal.ITIMER_REAL, interval, interval)

    bad = 0
    samples = []
    for i in range(n):
        dec = Cipher(algorithms.AES(KEY), modes.GCM(NONCE, tag)).decryptor()
        try:
            nbytes = dec.update_into(ct, out)
            dec.finalize()  # verifies the GCM tag
            tag_ok = True
        except Exception as e:  # InvalidTag etc.
            tag_ok = False
            nbytes = len(ct)

        body = bytes(out[:psize])
        if body != plaintext:
            bad += 1
            off = next((j for j in range(psize) if body[j] != FILL), -1)
            blk = (off // 16) * 16 if off >= 0 else -1
            if len(samples) < 12:
                samples.append((i, off, blk, tag_ok,
                                bytes(out[blk:blk + 16]).hex() if blk >= 0 else "?"))
        if i % 500 == 0:
            print("iter", i, "bad", bad, "ticks", _ticks, flush=True)

    if interval > 0:
        signal.setitimer(signal.ITIMER_REAL, 0, 0)

    print("TOTAL bad=%d / %d (psize=%d, interval=%gs, ticks=%d)"
          % (bad, n, psize, interval, _ticks), flush=True)
    for (i, off, blk, tag_ok, blkhex) in samples:
        print("  iter=%d firstdiff=%d block=%d tag_ok=%s bytes=%s"
              % (i, off, blk, tag_ok, blkhex))
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
