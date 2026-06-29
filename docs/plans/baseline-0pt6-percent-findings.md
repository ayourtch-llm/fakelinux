# Baseline corruption (~0.6%): signal-independent, x18-path-independent

Summary of findings from the gcm_signal_corruption_mmap.py repro under
fakelinux that pin down the **signal-INDEPENDENT** ~0.6% corruption
baseline as distinct from the ~2.9pp signal-forwarding delta.

## Three-component decomposition at N=80,000

```
Canonical (signals forwarded):              bad = 2,735 / 80,000 = 3.42%
SIG_IGN (signals fire, kernel-dropped):     bad =   410 / 80,000 = 0.51%
interval=0 (no itimer):                     bad =   540 / 80,000 = 0.68%
FRESH buffer + interval=0:                  bad =   481 / 80,000 = 0.60%
NO_X18_TRAMP + interval=0:                  bad =   477 / 80,000 = 0.60%
```

The signal-independent baseline is real (~0.6%, not noise) and
independent of buffer reuse and x18 trampolining.

## openssl AES_encrypt uses x18 (13 of 222 instructions)

Static disasm of `_rust.abi3.so` AES_encrypt routine at file offset
0x374a28, size 0x378 (222 instructions). 13 instructions touch x18.
Notably:

```
+0x90   2a1203f2  ORR  W18, WZR, W18    (MOV W18,W18 — 32-bit move)
+0xd0   b87278f3  LDR  W19, [X7, W18, UXTW]    (T-table index via w18)
+0xdc   b87178f2  LDR  W18, [X7, W17, UXTW]
+0xec   4a1200a5  EOR  W5, W5, W18
+0xfc   294144d2  LDP  W18, W17, [X6, #8]      ← BOTH x18 AND x17 in one insn
+0x10c  4a120063  EOR  W3, W3, W18
+0x158  53187c72  UBFM W18, W3, #24, #31       (byte extraction to w18)
+0x1c8  b8727932  LDR  W18, [X9, W18, UXTW]
+0x1d8  4a160252  EOR  W18, W18, W22
+0x1e4  4a030243  EOR  W3, W18, W3
+0x1fc  d3483cb2  UBFM X18, X5, #8, #15        (byte extraction to x18, 64-bit)
+0x2c0  2a1203f2  ORR  W18, WZR, W18
```

This is openssl's table-driven scalar AES_encrypt — x18 used as a state
register and table index. The instruction at +0xfc (`LDP W18, W17`) is
the trampoline's hardest case: a single instruction whose Rt=18 and
Rt2=17 means the default scratch pair (x16, x17) would alias Rt2.
`pick_scratch_pair` correctly avoids this by picking (16, 15) — the
trampoline rewrites the instr to `LDP W15, W17, [X6, #8]`, stores w15
to TSD as the new guest x18, and pops (s1=x16, s2=x15) from stack on
exit. x17 is loaded normally and not touched by the trampoline. Correct.

## Why "x18 path ruled out"

Both modes — trampoline-island execution AND SIGILL→emul fallback —
produce the same ~0.6% baseline at interval=0. Different code paths,
different code, but identical baseline rate. Either both paths have
the same subtle bug for the same instruction (improbable given they
are independent implementations) OR neither is the cause.

The same logic rules out the TPIDR_EL0 emul path: NO_X18_TRAMP also
disables TPIDR trampolines (tpidr=32.7M emul events in the 80k run),
yet the baseline is unchanged. TPIDR path is symmetrically ruled out.

## What's left (open)

The bug is signal-independent, buffer-reuse-independent,
x18-path-independent, TPIDR-path-independent, fakelinux-specific
(native macOS at matched density is 0/8000). Per the "wrong inputs /
wrong code / wrong execution" trichotomy with all of those ruled out,
some architectural state we have not yet enumerated must be perturbed
by what fakelinux does during normal openssl execution.

Concrete remaining unexplored angles:
  - Disassemble the trampoline-island IR-pcode actually emitted for the
    specific x18-using instructions in AES_encrypt and execute them in
    isolation with controlled inputs. If island output != architectural
    behavior on rare inputs, the path is structurally broken.
  - Loader / ET_EXEC / .so relocation: runs once at startup but if it
    left wrong code in libcrypto's AES_encrypt, the corruption would be
    deterministic per-iteration (not 0.6%). Unlikely.
  - lazy try_lazy_exec_fixup in segv path: per-iter rare.
  - Per-syscall trap_handler side effects: 2,980 syscalls at interval=0
    (~0.04 per iter) — too few to drive 0.6% iter-corruption directly.
