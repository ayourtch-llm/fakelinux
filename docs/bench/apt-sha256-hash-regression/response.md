# Expected response — apt-get SHA-256 regression

> **STATUS: OPEN / UNSOLVED as of 2026-06-29.** The ground-truth root cause is
> not yet known. This file currently records the **acceptance criteria** (which
> are gradeable even without the root cause), the **facts any correct solution
> must be consistent with**, and the **leading hypotheses**. Fill in the
> "Root cause" and "Fix" sections once solved.

## Acceptance criteria (gradeable)

A candidate fix passes iff, applied on top of commit `8a9ddf2…`:

1. **apt hashes correctly:** `scripts/rootfs-shell.sh 'rm -rf /var/lib/apt/lists/*; apt-get update'`
   produces **0** occurrences of `Hash Sum mismatch` (network/mirror "Failed to
   fetch" without a hash mismatch is acceptable — that's upstream).
2. **GCM fix preserved:** `tests/repro/gcm_signal_corruption.py` (in-guest) stays
   at **0** corruption for `interval=0` and `200µs SIGALRM`, AND the VPP
   `test_ipsec_esp.Test_openssl_ESNoff_ARoff_AES_GCM_128_NONE` test passes.
3. **No collateral:** `tests/smoke/apt-get-update.sh` still PASSES, and standalone
   `sha256sum/sha1sum/md5sum` remain correct.

A pure revert of `f9f2f60` fails criterion 2 and does not count.

## Facts a correct diagnosis must be consistent with

- Bug is **apt-specific scalar SHA-256**, not the SIMD/`sha256h` path (standalone
  hashes are correct).
- **`f9f2f60`-introduced** (boundary: `bb0bf6e` clean → `f9f2f60` broken). The
  delta is: the patcher now reaches DSOs mapped past their ELF header.
- apt's SHA-256 transform is **not directly patched** (no x18/SVC/TPIDR in it);
  the newly-patched libapt-pkg code is `pkgCache::sHash` + `Hashes::~Hashes`.
- **Deterministic**, and **identical under both** the trampoline and
  `NO_X18_TRAMP` fallback paths.
- The `w`-register arithmetic emulators look correct in isolation.

⟹ The mechanism is almost certainly a **side effect** of the expanded patching
(memory/state corruption, a patched site whose effect bleeds into the hash
path, or a behaviour that only manifests once this code is patched) — NOT a
direct mis-emulation of the SHA-256 instructions.

## Leading hypotheses (at authoring time — not confirmed)

1. A patched site (`sHash` / `~Hashes`, or another newly-reached apt DSO)
   corrupts memory or a register/TLS slot the SHA-256 path later reads. Trace
   every newly-patched instruction apt executes and diff apt's SHA-256 state /
   the hashed buffer against a known-good (`bb0bf6e`) run.
2. The patcher's section/range projection for one of apt's DSOs is slightly off,
   so a patch lands on a SHA-256 constant table or adjacent instruction (a
   precise-range bug, analogous to the force-phdr `.rodata` issue but in
   section mode).
3. A common-to-both-paths defect in how a specific patched instruction's effect
   (or the TSD-x18 / TPIDR / SVC handling) is applied, exposed only now that
   this code is patched — the `Hashes::~Hashes` (destructor) or an SVC/TPIDR
   patch is a candidate worth tracing.

## Root cause

_TODO — fill in when solved._

## Fix

_TODO — fill in when solved (commit hash, the change, and which hypothesis held)._

## Grading rubric (preliminary)

- **Full credit:** identifies the exact newly-patched site/mechanism that
  corrupts apt's SHA-256 and lands a fix meeting all 3 acceptance criteria.
- **Strong partial:** correctly localizes the corrupting patch (which
  instruction/DSO and how it bleeds into the hash) without a complete fix.
- **Partial:** reproduces + confirms the isolation (apt-scalar-SHA-256,
  f9f2f60-introduced, side-effect not direct mis-emulation) and proposes a
  decisive trace, without localizing the site.
- **Weak:** blames the standalone/SIMD SHA-256, calls it a network/mirror issue,
  or "fixes" it by reverting `f9f2f60`.
