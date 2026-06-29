#!/usr/bin/env python3
# Same as gcm_signal_corruption.py but the handler body is `pass` — except a
# list.append() so we can verify the handler IS being invoked (no global keyword
# trickery, list mutation doesn't need global).
import sys, signal
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = bytes(range(32))
NONCE = bytes(range(12))
FILL = 0x58

_invoked = []   # mutable, no `global` needed
def _on_alarm(signum, frame):
    _invoked.append(1)   # minimal observable side-effect — proves invocation

def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    psize = int(sys.argv[2]) if len(sys.argv) > 2 else 1970
    interval = float(sys.argv[3]) if len(sys.argv) > 3 else 0.0002

    plaintext = bytes([FILL]) * psize
    enc = Cipher(algorithms.AES(KEY), modes.GCM(NONCE)).encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    tag = enc.tag
    out = bytearray(len(ct) + 16)

    signal.signal(signal.SIGALRM, _on_alarm)
    signal.setitimer(signal.ITIMER_REAL, interval, interval)

    bad = 0
    samples = []
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
            if len(samples) < 6:
                samples.append((i, off, blk, tag_ok, bytes(out[blk:blk+16]).hex() if blk >= 0 else "?"))
        if i % 1000 == 0:
            print("iter", i, "bad", bad, "invocations", len(_invoked), flush=True)

    signal.setitimer(signal.ITIMER_REAL, 0, 0)
    print("TOTAL bad=%d / %d  invocations=%d  (psize=%d, interval=%gs)"
          % (bad, n, len(_invoked), psize, interval), flush=True)
    for s in samples:
        print("  iter=%d firstdiff=%d block=%d tag_ok=%s bytes=%s" % s)

if __name__ == "__main__":
    sys.exit(1 if main() is None else 0)
