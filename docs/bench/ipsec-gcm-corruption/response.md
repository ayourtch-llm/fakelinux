# Expected response — ground truth + grading rubric

This is the reference answer for the [`request.md`](request.md) benchmark.
The bug was solved in commit `f9f2f60` (the child of the benchmark's pre-fix
commit `bb0bf6e`); the canonical write-up is `docs/plans/...` §A.4.30.

## Root cause (the answer)

**`fakelinux`'s runtime code patcher silently skipped x18 patching for python
`cryptography`'s bundled `_rust.abi3.so`.** The dynamic linker maps that DSO's
executable region starting at an **executable `PT_LOAD` file offset, not at the
ELF header**. The in-memory code-range extractor
(`extract_code_ranges_from_memory`) looks for `\x7fELF` at the mapping base,
sees non-ELF bytes, and **returns zero code ranges**. Because the runtime-DSO
patch path (`patch_new_code_with_ranges`) is *restrictive* (no ranges ⇒ patch
nothing — unlike the permissive initial-binary path `rewrite_svc_instructions`),
**~2,736 x18-referencing instructions in that DSO were left UNPATCHED**.

Those instructions then executed on **real hardware x18**, which **macOS zeroes
on every kernel entry** (syscall, signal delivery, preemption — a documented
platform constraint fakelinux is built around). Any kernel entry while
`AES_encrypt` held live data in hw x18 → x18 becomes 0 → garbage AES output →
corrupt decrypted block (with a still-valid GCM tag, since the ciphertext input
was untouched).

## Why this reconciles every observation

- **fakelinux-specific:** macOS-built openssl never emits x18 (reserved on the
  platform); only the *Linux* binary does.
- **signal-independent baseline (~0.6%):** ordinary syscalls/preemption zero x18
  during the decrypt, no signal required.
- **+2.9pp under SIGALRM:** signals are simply *more* kernel entries.
- **every in-process state probe "clean":** the corruptor is the **kernel
  zeroing hw x18** between instructions — invisible to any probe that inspects
  fakelinux-mediated saved/restored state.
- **"common to both AES paths":** the *whole DSO `.text`* was unpatched, so it
  is upstream of the NEON-vs-scalar split — "both modes corrupt ⇒ not x18" is a
  **non-sequitur**.

## The load-bearing reasoning step (what a strong agent must catch)

The trail's `AES_X18_SCAN` "proved x18 is patched" — but it scanned the **system
`libcrypto.so.3`** (which *was* patched) and/or a **stale TPIDR-only patch
cache**, **not the vendored `_rust.abi3.so`** that python's `cryptography`
actually calls. The benchmark's whole difficulty is that the documented
"x18 ruled out" conclusion is **false**, retracting the (correct) earlier
hypothesis. The required insight: *"is this instruction patched?" must be asked
of the **exact loaded DSO the code runs in**, with a fresh patch cache — not a
sibling library.* Equivalent decisive checks an agent could run:
- Trace per-DSO patch stats and notice `_rust.abi3.so`: `0 x18 (N skipped, no
  code ranges)` while `libcrypto.so.3` is patched.
- Note that `extract_code_ranges_from_memory` returns empty whenever the mapping
  doesn't begin with `\x7fELF`, and that runtime-DSO patching is gated on having
  ranges.
- A minimal C EVP-AES-GCM repro: system `libcrypto` clean vs the vendored DSO
  corrupt (committed as `tests/repro/gcm_evp_fixed.c`).

## The fix

Derive executable code ranges from the **backing ELF file** for file-backed
runtime mappings, instead of relying on finding the ELF header in the mapping:
- `extract_code_ranges_from_file_mapping(fd, map_start, map_len, map_file_off)`
  reads `SHF_EXECINSTR` section ranges (and, for robustness, `PF_X PT_LOAD`
  program-header segments) from the file and projects them into the mapping
  window. Used by `patch_new_code_file`.
- Bump `PATCH_CACHE_VERSION` to invalidate stale (TPIDR-only) cache entries.

## Verification (must reach 0)

- `_rust.abi3.so` x18 instructions patched: `0 → ~2736`.
- `tests/repro/gcm_signal_corruption.py`: **0 corruption** across
  `interval=0` default (0/80000), `interval=0 armcap=0` (0/20000), and 200µs
  `SIGALRM` default & `armcap=0` (0/8000).
- VPP `test_ipsec_esp.Test_openssl_ESNoff_ARoff_AES_GCM_128_NONE`: **PASS**
  (was 100% FAIL) — and broadly the `test_ipsec_*` family recovers.
- `cargo test --release patch_cache` passes.

## Grading rubric

- **Full credit:** identifies that x18 patching is skipped for the runtime-loaded
  DSO because its mapping starts past the ELF header (empty code ranges) → native
  hw x18 zeroed by macOS → corruption; AND explicitly flags that the
  "x18 ruled out / AES_X18_SCAN" conclusion is wrong because it checked the wrong
  DSO / stale cache. Proposes reading code ranges from the backing ELF file.
- **Strong partial:** identifies "the DSO's x18 instructions are running
  unpatched → macOS zeroes hw x18 → corruption" but doesn't pin down *why* the
  patcher skipped them (the ELF-header-offset / empty-ranges mechanism).
- **Partial:** correctly rejects the "x18 ruled out" claim and proposes a
  decisive way to test x18-patching of the *actual* DSO (per-DSO patch trace,
  minimal-C discriminator), without yet naming the loader mechanism.
- **Weak:** restates the paradox, proposes more in-process state probes, or
  accepts the documented "ruled out" list. (This is the failure mode that kept
  the bug unsolved across multiple single-agent sessions.)
- **Bonus:** a fix-review catching robustness gaps — e.g. stripped DSOs
  (no section headers) still fall through to the broken in-memory extractor
  unless a `PF_X PT_LOAD` program-header fallback is added; the asymmetry between
  the permissive initial-load patch path and the restrictive runtime-DSO path;
  confirming i-cache is invalidated after patching.

## Provenance

Solved 2026-06-29 in a multi-agent run: an exhaustive 13-probe sweep
(Opus 4.7) eliminated every in-process state hypothesis — which is what made the
loader gap the answer by elimination — and a fresh model (codex/gpt-5.5),
explicitly told to challenge the "ruled out" list, found the loader mechanism
and wrote the fix. An independent third model (GLM-5.2) reasoned to the same
root cause and reviewed the fix (`docs/reports/glm-gcm-corruption-analysis.md`).
The key lesson the benchmark tests: **distrust a "ruled out" that rests on a
probe of the wrong artifact.**
