# Expected response — apt-get SHA-256 regression

> **STATUS: SOLVED 2026-06-29.** Root cause and fix below. Hypothesis #2 (a
> patched site landing on a SHA-256 constant table) was correct — with one
> twist the original isolation got wrong: the table is in **libgcrypt**, not
> libapt-pkg. apt computes its hashes via `gcry_md_*`, not its own code.

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

The patcher **overwrote SHA-256 round constants, mistaking the K-table for code.**

- apt computes SHA-256 via **libgcrypt** (`gcry_md_write`/`gcry_md_read`,
  imported `GCRYPT_1.6`) — *not* libapt-pkg's own code. (Standalone
  `sha256sum` is coreutils → **libcrypto/OpenSSL**, a different implementation,
  hence correct. That's why the two disagree.)
- libgcrypt's ARMv8-CE SHA-256 transform is hand-written asm. Its 64-word
  `K[]` round-constant table is emitted **inline in the executable `.text`
  section** (file offset/vaddr `0xa1450` in `libgcrypt.so.20.4.3`), in an
  **inter-function gap with no `.eh_frame` FDE**.
- On Linux, x18 is an unreserved GPR, so `references_x18` legitimately flags
  ~1494 real instructions in libgcrypt — but it *also* flags **9 of the 64 K
  constants** that happen to have a GPR field == 18 (e.g. `K[4]=0x3956c25b`
  decodes as `ldrb w27,[x18,#0x5b0]`; `K[63]=0xc67178f2` as `… x18`).
- `f9f2f60` made the patcher reach DSOs mapped past their ELF header via
  `extract_code_ranges_from_file_mapping`, which uses **only section headers
  (`SHF_EXECINSTR`)** — the *entire* `.text` is treated as code. The precise
  `.eh_frame` FDE strategy (used by the in-memory extractor) would have
  excluded the no-FDE K-table; the section strategy does not. So those 9 K
  constants got rewritten to UDF/trampoline branches → **corrupt K-table →
  wrong SHA-256**, deterministically and identically under both x18 paths.
- SHA-1/MD5 share the hash plumbing but have different constants that don't
  collide with x18 encodings → unaffected. The real transform code uses
  `x0/x1/x3` + NEON (`sha256h`), **no x18** — so excluding the table loses no
  real patch.

The removed "SHA-256 K-table fingerprint" guard (loader.rs `find_literal_pools`
comment) had been deleted on the assumption that the FDE strategy always
excludes such tables. That holds for the in-memory path but **not** for the
section-mode file path `f9f2f60` introduced.

## Fix

`src/loader.rs`: added `find_crypto_const_tables(start, len)` — detects SHA-256
(64×u32) and SHA-512 (80×u64) K-tables by their leading-constant signature and
returns their byte ranges; `patch_new_code_with_ranges` now adds those ranges
to the `literal_pools` exclusion so the x18 patcher skips them. Surgical,
matches only exact crypto-constant signatures, never excludes real code.

Verification: `apt-get update` → 0 `Hash Sum mismatch` (19/19 indexes fetched
& verified); `gcm_evp_fixed 8000 1970 200` → `bad=0`; standalone
sha256/sha1/md5 correct; `tests/smoke/apt-get-update.sh` PASS.

**Hypothesis #2 held** (modulo the libapt-pkg→libgcrypt correction).

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
