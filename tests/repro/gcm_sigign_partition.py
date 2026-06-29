#!/usr/bin/env python3
# SIG_IGN partition test: itimer still fires, but Python sets SIG_IGN so
# fakelinux's install_forwarder routes to native libc::SIG_IGN — macOS
# kernel DROPS the signal at the kernel level. signal_forwarder is NOT
# called at all (verify via FORWARDER_CALLS == 0 in TRAP_STATS2).
#   - bad=0  -> corruption requires the signal to actually reach userspace.
#   - bad>0  -> corruption happens without any user-side delivery — would
#               be a shock and points at something extraordinary.
import sys, signal
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = bytes(range(32)); NONCE = bytes(range(12)); FILL = 0x58

def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    psize = int(sys.argv[2]) if len(sys.argv) > 2 else 1970
    interval = float(sys.argv[3]) if len(sys.argv) > 3 else 0.0002
    plaintext = bytes([FILL]) * psize
    enc = Cipher(algorithms.AES(KEY), modes.GCM(NONCE)).encryptor()
    ct = enc.update(plaintext) + enc.finalize(); tag = enc.tag
    out = bytearray(len(ct) + 16)
    # KEY KNOB:
    signal.signal(signal.SIGALRM, signal.SIG_IGN)
    signal.setitimer(signal.ITIMER_REAL, interval, interval)
    bad = 0
    for i in range(n):
        dec = Cipher(algorithms.AES(KEY), modes.GCM(NONCE, tag)).decryptor()
        try:
            dec.update_into(ct, out); dec.finalize()
        except Exception: pass
        if bytes(out[:psize]) != plaintext:
            bad += 1
        if i % 1000 == 0:
            print("iter", i, "bad", bad, flush=True)
    signal.setitimer(signal.ITIMER_REAL, 0, 0)
    print("TOTAL bad=%d / %d (psize=%d, interval=%gs)" % (bad, n, psize, interval))
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
