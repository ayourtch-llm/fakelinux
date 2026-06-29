#!/usr/bin/env python3
"""mmap-backed variant of gcm_signal_corruption.py for FAKELINUX_WATCH.

The canonical repro uses bytearray() which lives in Python's brk heap — fakelinux
WATCH only arms on anonymous mmap()s. This variant allocates the decrypt output
buffer via mmap.mmap(-1, 0x100000) so:
  - The buffer is in its own anonymous mapping (so WATCH seq:len matches).
  - The mapping is 1 MB (page-aligned, unique length) → seq=1 trivially.
  - The first ~2KB hold the decrypt active region; the rest (>1 MB - 2 KB) is
    UNTOUCHED by openssl — that's the WATCH target. If stray writes scatter
    beyond the active region (as the bug's signature suggests), the tail will
    catch them with zero perturbation from legitimate decrypt stores.

USAGE
    # (1) Run once without WATCH to print out_buf and confirm bad count.
    scripts/vpp-shell.sh '/root/vpp/build-root/test/venv/bin/python3 \
        /tmp/gcm_signal_corruption_mmap.py 40000 1970'

    # (2) Re-run with WATCH armed on a tail page (offset 0x10000 = 64 KB in):
    FAKELINUX_WATCH=1:100000:10000 scripts/vpp-shell.sh \
        '/root/vpp/build-root/test/venv/bin/python3 \
         /tmp/gcm_signal_corruption_mmap.py 40000 1970'

Args: [iterations] [payload_size_bytes] [sigalrm_interval_seconds]
Defaults: 40000 iters, 1970-byte payload, 200us SIGALRM.
"""
import ctypes
import mmap
import os
import signal
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = bytes(range(32))
NONCE = bytes(range(12))
FILL = 0x58
# Anonymous mmap is kernel-zero-initialized, so the tail sentinel is 0x00.
# Pre-filling would itself write to the watched page and disarm WATCH.
TAIL_PATTERN = 0x00
MMAP_LEN = 0x123000  # 1 MB + 140 KB — odd length so Python-startup mmaps
                     # (which use round sizes) don't collide with seq=1
WATCH_TAIL_OFFSET = 0x100000  # 1 MB into the buffer — deep tail

_ticks = 0
def _on_alarm(signum, frame):
    global _ticks
    _ticks += 1

def main() -> int:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 40000
    psize = int(sys.argv[2]) if len(sys.argv) > 2 else 1970
    interval = float(sys.argv[3]) if len(sys.argv) > 3 else 0.0002

    plaintext = bytes([FILL]) * psize
    enc = Cipher(algorithms.AES(KEY), modes.GCM(NONCE)).encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    tag = enc.tag

    out = mmap.mmap(-1, MMAP_LEN)
    # NO pre-fill: any write to the watched page disarms WATCH. Anonymous mmap
    # is kernel-zeroed, so a stray write is detected as a non-zero tail byte.

    addr = ctypes.addressof(ctypes.c_char.from_buffer(out))
    print("fakelinux gcm-mmap repro: out_buf=%#x mmap_len=%#x psize=%d iters=%d interval=%gs"
          % (addr, MMAP_LEN, psize, n, interval), flush=True)
    print("  active region: [%#x .. %#x)   tail watch target: page at out_buf+%#x"
          % (addr, addr + psize, WATCH_TAIL_OFFSET), flush=True)
    print("  ARM WATCH WITH: FAKELINUX_WATCH=1:100000:%x" % WATCH_TAIL_OFFSET, flush=True)

    if interval > 0:
        signal.signal(signal.SIGALRM, _on_alarm)
        signal.setitimer(signal.ITIMER_REAL, interval, interval)

    bad = 0
    tail_hits = 0
    samples = []
    tail_samples = []
    for i in range(n):
        dec = Cipher(algorithms.AES(KEY), modes.GCM(NONCE, tag)).decryptor()
        try:
            dec.update_into(ct, out)
            dec.finalize()
            tag_ok = True
        except Exception:
            tag_ok = False

        body = bytes(out[:psize])
        if body != plaintext:
            bad += 1
            off = next((j for j in range(psize) if body[j] != FILL), -1)
            blk = (off // 16) * 16 if off >= 0 else -1
            if len(samples) < 12:
                samples.append((i, off, blk, tag_ok,
                                bytes(out[blk:blk + 16]).hex() if blk >= 0 else "?"))

        # Sample tail (cheap stride scan).
        if i % 5 == 0:
            tail_mv = memoryview(out)[psize:]
            for stride_off in range(0, len(tail_mv), 0x1000):
                if tail_mv[stride_off] != TAIL_PATTERN:
                    tail_hits += 1
                    if len(tail_samples) < 12:
                        tail_samples.append((i, psize + stride_off,
                                             bytes(out[psize+stride_off:psize+stride_off+16]).hex()))
                    break

        if i % 1000 == 0:
            print("iter", i, "bad", bad, "tail_hits", tail_hits, "ticks", _ticks, flush=True)

    if interval > 0:
        signal.setitimer(signal.ITIMER_REAL, 0, 0)

    print("TOTAL bad=%d tail_hits=%d / %d (psize=%d, interval=%gs, ticks=%d)"
          % (bad, tail_hits, n, psize, interval, _ticks), flush=True)
    for (i, off, blk, tag_ok, blkhex) in samples:
        print("  iter=%d firstdiff=%d block=%d tag_ok=%s bytes=%s"
              % (i, off, blk, tag_ok, blkhex))
    for s in tail_samples:
        print("  TAIL iter=%d off=%#x bytes=%s" % s)
    return 1 if (bad or tail_hits) else 0

if __name__ == "__main__":
    sys.exit(main())
