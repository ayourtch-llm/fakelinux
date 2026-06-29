# Agent debugging benchmark — apt-get SHA-256 regression (OPEN)

> **Status: UNSOLVED as of 2026-06-29.** This benchmark was authored *before* the
> root cause was known — it captures a real, reproducible, isolated regression.
> `response.md` records the acceptance criteria and known facts; the ground-truth
> root cause is to be filled in once solved.

## How to use this benchmark

```
git checkout 8a9ddf2f885b186343e634cdc9eea55dc21756db
```

At this commit, the IPsec/GCM corruption is fixed (commit `f9f2f60`, the parent
chain), but a **new regression** has appeared: `apt-get update` inside the guest
fails SHA-256 verification of the package indexes. Find the root cause and fix it
**without** regressing the GCM fix.

## Symptom

`scripts/rootfs-shell.sh 'apt-get update'` reports, for several index files:

```
E: Failed to fetch http://ports.ubuntu.com/... Hash Sum mismatch
   Hashes of expected file:
    - Filesize:1325212   SHA256:b1e6e2466c80...  SHA1:14096f1ed0cb...  MD5Sum:2ecb136fb600...
   Hashes of received file:
    - SHA256:64f8742c80d4...  SHA1:14096f1ed0cb...  MD5Sum:2ecb136fb600...  Filesize:1325212
```

The decisive detail: **SHA1, MD5, and Filesize all MATCH; only the SHA256
differs.** Identical content cannot yield a different SHA-256 — so fakelinux is
**computing SHA-256 wrong** for apt, *deterministically* (same wrong hash every
run, same value under both x18 paths).

## What is already isolated (don't re-derive — build on it)

- **apt-specific scalar SHA-256.** Standalone `printf test | sha256sum` (and
  `sha1sum`, `md5sum`) all return the **correct** values. `coreutils`/`libcrypto`
  (the SIMD `sha256h` path) is fine. The bug is in apt's *own* scalar
  `SHA256Summation` (in `libapt-pkg.so.6.0`, which has 0 `sha256h` instructions).
- **Regression boundary:** at commit `bb0bf6e` (parent of `f9f2f60`) `apt-get
  update` hashes correctly (0 mismatches). At `f9f2f60`/HEAD it breaks. So
  **`f9f2f60` introduced it.** `f9f2f60` made the x18 patcher reach DSOs whose
  runtime mapping starts past the ELF header (previously those were left
  unpatched). So *more code is now patched*, including some of apt's.
- **The patched libapt-pkg code is NOT the SHA-256 transform.** The only
  x18-referencing instructions in libapt-pkg are 6, all in `pkgCache::sHash` (a
  string hash: `ldrb; orr w,w,#0x20; mul; madd`) and `Hashes::~Hashes`. apt's
  SHA-256 function contains no x18/SVC/MRS-tpidr to patch. **So the SHA-256 code
  itself is not directly rewritten — yet its output is wrong.**
- **Both x18 paths break it identically** (default trampoline and
  `FAKELINUX_NO_X18_TRAMP=1` fallback emulation each yield the same 8 mismatches)
  → the cause is common to both, not a trampoline-vs-emul difference.
- The `madd/mul/orr`-immediate emulators (`emul_dp3_src`, `emul_logical_imm` in
  `src/trap.rs`) handle the `w`-register (32-bit) case correctly on inspection.
- `tests/smoke/apt-get-update.sh` **PASSES** here (it only checks that apt-get
  *loads/runs*, not that it hashes correctly) — so that smoke test does NOT catch
  this bug. A correct fix should make a *hash-correctness* check pass too.

## The trap

Every obvious probe says "fine": standalone hashes are correct, the binary loads
and runs, the patched instructions emulate correctly, and the SHA-256 code isn't
even patched. Yet apt's SHA-256 is deterministically wrong. The cause is a
**side effect** of the expanded patching on some state the SHA-256 path depends
on — not a direct mis-emulation of the hash code.

## Task

Diagnose the precise mechanism by which `f9f2f60`'s expanded x18/SVC/TPIDR
patching causes apt's scalar SHA-256 to compute a wrong digest, and fix it so
that **both** of the following hold (see `response.md` for the gradeable
acceptance test):

1. `apt-get update` produces **no SHA-256-only `Hash Sum mismatch`**.
2. The GCM fix is preserved: `tests/repro/gcm_signal_corruption.py` stays at 0
   corruption and the VPP `test_ipsec_esp` GCM test still passes.

A naïve "revert `f9f2f60`" does **not** count — it re-introduces the GCM bug.
