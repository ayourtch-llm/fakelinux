# Independent Analysis: AES-GCM Corruption Under fakelinux

**Author:** GLM-5.2 (independent investigator, multi-model investigation)
**Date:** 2026-06-29
**Status:** ROOT CAUSE CONFIRMED (by codex/gpt-5.5) mid-investigation; this report
incorporates the confirmed outcome, my independent reasoning toward the same
conclusion, and a fresh-eyes review of the fix (commit `f9f2f60`).

---

## 1. Executive summary

The bug was **NOT in signal handling, NOT in the x18 trampoline islands, NOT in
NEON save/restore, NOT in memory aliasing, and NOT in any of the 13 state probes.**
It was in the **loader's code-range extraction**: when the dynamic linker mapped
`_rust.abi3.so` (the `cryptography` wheel's vendored Rust/crypto DSO) starting at
a PT_LOAD file offset rather than at the ELF header, `extract_code_ranges_from_memory()`
saw non-ELF bytes at the mapping base, returned **zero code ranges**, and the patcher
**skipped all 2736 x18-referencing instructions**. Those instructions then executed
on real hardware x18, which the macOS kernel **zeroes on every kernel entry**
(syscall, signal delivery, preemption). Zeroed x18 fed into the AES table-lookup
code → garbage keystream → corrupt decrypted block. A valid GCM tag (computed over
the intact ciphertext) in ~95% of cases confirmed the write was post-decrypt.

This was signal-**amplified** but signal-**independent**: any kernel entry (including
the ~0.04 syscalls/iter from Python between decrypts, and kernel preemption) zeroes
hw x18. Aggressive SIGALRM simply raised the kernel-entry rate, turning ~0.6% baseline
into ~3.4%.

My independent investigation (before learning of codex's fix) was converging on
exactly the **loader/code-patching** path as the most likely remaining suspect, and
had independently identified two concrete leads in that area (see §3). The resolution
vindicates the core deductive principle that the prior probes had implicitly
established: **correct committed architectural inputs + correct code + correct CPU
⟹ correct output is mandatory; therefore SOME input was wrong at execution time
even though every probe saw it correct at observation time.** The resolution: the
"input" that was wrong was the **instruction stream itself** — specifically, x18-referencing
instructions that should have been rewritten to use the TSD-backed trampoline but
weren't. The P4 code-integrity probe verified bytes matched a first-hit reference —
but both reference and sample were the ORIGINAL unpatched bytes, so they matched
each other. No probe had an independent ground truth for what the bytes *should*
have been, and no probe verified the patcher had ever *visited* this DSO.

---

## 2. My independent assessment (written before seeing the fix)

### 2.1 The paradox and why it is NOT a paradox

The trail hit a "wall" (A.4.17): every fakelinux-mediated state crossing is
bit-perfect, the resume state matches the frame, native macOS is clean even at higher
signal density, yet fakelinux-specific corruption persists.

This paradox — *correct inputs + correct code + correct CPU ⟹ wrong output* — is
**logically impossible** for a deterministic single-threaded computation. AES is
deterministic. Therefore one of the three premises was **false at the moment of
computation**, even though every probe found it true **at the moment of observation**.

The key deductive insight: **all 13 probes observe state at discrete checkpoints**
(signal entry, signal exit, the corrupting store, the resume trap). They cannot
observe a **transient** discrepancy during the AES rounds that is already healed
by the time the next checkpoint fires. So the investigation needed to look for
something that is (a) transiently wrong during AES execution, (b) correct at every
checkpoint, and (c) fakelinux-specific.

### 2.2 Where I poked holes in the "ruled out" list

#### Hole 1: "Both x18 paths corrupt ⟹ not x18" is a NON SEQUITUR if the bug is upstream of the path split

`FAKELINUX_NO_X18_TRAMP=1` still corrupts, which was taken to rule out x18. But
`NO_X18_TRAMP` only changes HOW an x18 instruction is patched (inline island vs.
UDF→SIGILL→emulate). **Both modes still depend on the patcher having VISITED the
instruction in the first place.** If the patcher never scans a given DSO's `.text`
(because code-range extraction fails for that mapping), the instructions are
unpatched in BOTH modes. The A.4.14/A.4.24 conclusion "x18 ruled out" was therefore
only valid for DSOs the patcher correctly scanned — and no probe ever verified that
the patcher had actually *reached* `_rust.abi3.so`. This was the central logical gap.

#### Hole 2: AES_X18_SCAN checked the WRONG binary

A.4.29's retraction of A.4.28 relied on `AES_X18_SCAN` (commit `75c9f18`) to "prove"
all 13 scalar AES_encrypt x18 instructions were patched. But that scan targeted the
**system libcrypto.so.3** — which *was* correctly patched (its mapping starts at the
ELF header). The actual decrypt path goes through the **vendored** `_rust.abi3.so`
shipped inside the `cryptography` wheel, whose mapping geometry is different. No
probe ever verified patching of the binary that the repro actually executes. This is
a **probe-target mismatch** — the most dangerous class of false-negative, because
you get a confident "clean" result that is technically correct for the wrong
subject.

#### Hole 3: The probe chain has a coverage gap at the code-patching layer

Every probe in the suite (KS_PROBE, FWD_REG_PROBE, REG_PROBE, RK_PROBE, P4, P5,
RESUME_PROBE, code-integrity, altstack, forwarder-nested, CPSR/TPIDR/FPSR/FPCR)
verifies properties of the **runtime execution state**. **Not a single probe
verifies that the patcher has covered every executable mapping.** The patcher's
coverage was implicitly trusted. This is exactly the blind spot the user asked me
to look for in angle (1): *a flaw in the probe chain that "proves" the inputs are
correct.* The inputs ARE correct at the store — the problem is upstream: the wrong
instruction stream reached the CPU.

### 2.3 Where my investigation was pointing (pre-fix)

I had independently narrowed to the loader/patching path and identified two concrete
leads:

**Lead A — The I-cache invalidation asymmetry at patch sites (partially right, needs
the caveat in §5).** `patch_x18_with_trampoline` writes the `B <island>` branch into
guest `.text` at `src/x18_trampoline.rs:451,464` **without a local
`sys_icache_invalidate`** at the patch site (only the island code gets flushed inside
`emit()`). I flagged this as anomalous. As §5 shows, the *callers* in `do_mmap` /
`patch_trampoline_entry` do issue a covering `sys_icache_invalidate` afterward, so
this is not a live bug — but it is a fragile layering (the correctness depends on
every caller remembering to flush, and the `try_patch_from_cache` path flushes only
islands, leaning entirely on the outer caller).

**Lead B — The code-range extraction for non-header-aligned mappings (the actual
root cause).** I was about to investigate why `extract_code_ranges_from_memory()`
returns empty for mappings that don't begin at `\x7fELF` — which is exactly the bug.
The function's first check (`data[0..4] != ELFmagic ⟹ return empty`) silently
disables x18 patching for the entire mapping. The comment at `loader.rs:1066` makes
the assumption explicit ("Check ELF magic" at the mapping base) without acknowledging
that the dynamic linker routinely maps at PT_LOAD offsets past the ELF header.

---

## 3. The confirmed root cause (codex, commit `f9f2f60`)

### 3.1 Mechanism

```
_rust.abi3.so (vendored in cryptography wheel)
  └─ PT_LOAD R-X at file offset ≠ 0  (does NOT include the ELF header)
     └─ mmap(fd, offset=PT_LOAD.p_offset, ...)
        └─ patch_new_code_file(start, len, fd, offset)
           └─ try_patch_from_cache → HIT (stale TPIDR-only cache, v1)
              returns true with ZERO x18 sites — NO scan, NO log. (Bug amplified
              by cache; even without it the scan below also fails.)
           ── OR on a cache miss ──
           └─ extract_code_ranges_from_memory(start, len)
              └─ start[0..4] ≠ "\x7fELF"  ⟹  return Vec::new()  // NO code ranges!
                 └─ patch_new_code_with_ranges: have_code_ranges=false
                    └─ gate at loader.rs:921: `have_code_ranges && addr_in_code_ranges(...)`
                       FAILS at the first operand ⟹ 2736 x18 instrs SKIPPED
                       (line 929-931: x18_skipped++ — a log IS emitted here,
                        but the cache-hit path above bypasses this entirely)
                    └─ 2736 x18 instructions left running on hw x18
                       └─ macOS zeroes hw x18 on kernel entry
                          └─ garbage AES table-lookup ⟹ garbage keystream
                             └─ corrupt decrypted block (tag still valid)
```

**Critical asymmetry that explains the blast radius.** There are TWO code-patching
entry points with **opposite** x18 gating when code ranges are empty:

| Function | Gate when `have_code_ranges == false` | Used for |
|---|---|---|
| `rewrite_svc_instructions` (loader.rs:604) | `!have_code_ranges \|\| addr_in_code_ranges(...)` → **patches ALL x18** (permissive) | **Initial** binary + ld.so load |
| `patch_new_code_with_ranges` (loader.rs:921) | `have_code_ranges && addr_in_code_ranges(...)` → **patches NO x18** (restrictive) | **Runtime** DSO mmap (dlopen) |

The restrictive gate in the runtime path was intentionally added (comment at
loader.rs:918–920: "x18 patterns have high false-positive rates on data... Only
patch if we have confirmed code ranges") to avoid corrupting string tables in shared
library mappings. The safety check became a coverage failure: when code-range
extraction fails (non-header-aligned mapping), the safety check silently disables
ALL x18 patching for that DSO. This is why the initial binary (permissive path)
was fine but runtime-loaded `_rust.abi3.so` (restrictive path) was not.

### 3.2 How this reconciles EVERY piece of paradoxical evidence

| Observation | Explanation |
|---|---|
| ~0.6% baseline at interval=0 (no signals) | Kernel entries from Python's ~0.04 syscalls/iter + kernel preemption zero hw x18. No SIGALRM needed. |
| +2.9pp under aggressive SIGALRM | Each forwarded SIGALRM = 2 kernel entries (deliver + sigreturn), raising the hw-x18-zeroing rate. |
| Native macOS = 0% even at higher density | macOS-built openssl/libcrypto never uses x18 (reserved register); the vendored Linux-built `_rust.abi3.so` does. |
| `armcap=0` (scalar) and NEON-AES both corrupt at same rate | The DSO's ENTIRE .text was unpatched — both the scalar table-driven path (uses x18 as table index) and surrounding CTR/GCM code. The NEON-AES *inner* rounds don't use x18, but the DSO has other x18 sites in surrounding code that corrupt state. |
| `NO_X18_TRAMP` still corrupts | Both modes depend on the patcher visiting the DSO. It never did. The mode switch is downstream of the coverage failure. |
| All GPRs/NEON/cpsr/tpidr/fpsr/fpcr correct at the store | They ARE correct. The corruption source (hw x18=0) was consumed transiently inside AES_encrypt's table-lookup and folded into the keystream long before the store. By the store, x18 has been re-loaded from TSD by surrounding trampolined code (in other DSOs). |
| Round-key table, counter, keystream scratch — all correct | Correct. The wrong value came from a T-table lookup indexed by zeroed x18, not from corrupted memory. |
| Code bytes (P4_CODE/AES_FN) intact | Correct. The bytes in D-cache are the ORIGINAL (unpatched) instructions. P4 verified bytes match a reference — but the reference was also unpatched, so both matched. The probe couldn't distinguish "correct unpatched bytes" from "correct patched bytes." |
| 146/154 tag still valid | GHASH/tag is over the ciphertext INPUT (intact). The corruption is in the decrypted OUTPUT (post-CTR-XOR). The 8 tag-fails are cases where the zeroed-x18 path also corrupted the GHASH accumulation or ciphertext-input handling. |
| Foreign, time-varying garbage in the keystream | The T-table at `[base + x18_index]` with x18=0 reads T[0] — a fixed but "foreign-looking" value; combined with subsequent mixing it appears as time-varying garbage because DIFFERENT x18-using instructions are hit on different kernel-entry timings. |
| WATCH caught "openssl's own STUR x0 with wrong x1" | Correct. openssl computed a wrong keystream (via zeroed-x18 table lookup), stored it to the keystream scratch, then loaded it as x1. The store is correct; the computed value is wrong. WATCH exonerated fakelinux's own writes but couldn't see the hw-x18 zeroing inside native AES. |
| `x18_fallback` count very low (12–13k per 80k iters) | These are emulated instructions in CORRECTLY-PATCHED DSOs. The 2736 unpatched instructions in `_rust.abi3.so` execute NATIVELY (never trap), so they don't appear in fallback counts — making the trap stats misleadingly low. |
| RESUME_PROBE: hw == frame at resume | Correct. hw x18 is zeroed by the kernel DURING execution (between instructions), not at the resume point. By resume, the trampoline (in a patched DSO) has re-loaded TSD x18 into x17, and hw x18 is 0 — but the RESUME_PROBE doesn't sample hw x18 mid-AES, only at the sigreturn boundary. |

### 3.3 Why the prior investigation couldn't find it

1. **Probe-target mismatch:** AES_X18_SCAN checked system libcrypto.so.3, not the
   vendored _rust.abi3.so that the repro actually executes.
2. **Patch-cache staleness:** a TPIDR-only patch cache for _rust.abi3.so (written
   by an older version that also failed to find code ranges) was served as a cache
   hit, making `try_patch_from_cache` return `true` (fully applied) without any x18
   sites — giving the appearance that patching HAD run and found nothing to patch.
3. **The deductive frame "both x18 modes corrupt ⟹ not x18"** was applied without
   verifying that the precondition (the patcher reached the DSO) held for either mode.
4. **No probe verified patcher coverage.** The entire probe suite was downstream of
   the patcher, assuming it worked correctly.

---

## 4. Fresh-eyes review of the fix (`f9f2f60`)

### 4.1 What the fix does

Adds `extract_code_ranges_from_file_mapping(fd, map_start, map_len, map_file_off)`
which reads section headers from the **backing ELF file** via `pread` (not from the
mapping's memory) and projects `SHF_EXECINSTR` section ranges into the mapping
window using pure file-offset arithmetic. `patch_new_code_file` now calls this first,
falling back to the old `extract_code_ranges_from_memory` only if the file isn't a
valid little-endian ELF64 with section headers. `PATCH_CACHE_VERSION` is bumped
1→2 to invalidate stale caches.

### 4.2 Is the file-offset→mapping projection correct?

**Yes.** The arithmetic (`loader.rs:1033–1042`) is:

```
sh_end         = sh_offset + sh_size
overlap_start  = max(sh_offset, map_file_off)
overlap_end    = min(sh_end, map_file_off + map_len)
range_va       = map_start + (overlap_start - map_file_off)
range_len      = overlap_end - overlap_start
```

This is the standard interval-intersection + linear projection. It is correct
because `do_mmap` populates the mapping via `pread_full(fd, result_addr, read_len,
offset)`, establishing a faithful `result_addr + (file_off - offset) ⟹ file[file_off]`
relationship. The projection respects arbitrary mapping windows into the file.

### 4.3 Edge cases — assessed

| Edge case | Verdict |
|---|---|
| **Multiple exec sections** (.text, .text.hot, .init, .plt) | ✓ Correct. Iterates ALL `e_shnum` sections, collects every `SHF_EXECINSTR`. |
| **PIE vs non-PIE** | ✓ Correct. Uses file offsets (not `sh_addr` virtual addresses), so it's independent of load base. |
| **Section spanning mapping boundary** | ✓ Correct. The overlap clamp includes only the portion within `[map_file_off, map_file_off+map_len)`. |
| **Mapping partially past EOF** (`read_len < length`) | ✓ Correct. Sections don't extend past EOF; the projection only covers real file content. |
| **Multiple R-X PT_LOADs mapped separately** | ✓ Correct. Each mmap calls `patch_new_code_file` with its own `offset`; the projection window selects only sections overlapping that mapping. |
| **Stripped DSO** (`e_shoff == 0`) | ⚠️ **Falls back to `extract_code_ranges_from_memory`, which STILL FAILS** for non-header-aligned mappings. The old bug persists for stripped DSOs loaded past their ELF header. Rare in practice (DSOs usually retain section headers) but is a latent coverage gap. |
| **`e_shnum == 0`** (extended numbering, ≥0xFF00 sections) | ⚠️ Returns `None` (line 1004: `e_shnum == 0 ⟹ return None`). Falls back. Correct for normal binaries; misses pathologically-large section counts. Extremely rare. |
| **`sh_type` not checked** (unlike old Strategy 2 which requires `SHT_PROGBITS`) | ⚠️ The new function skips only on `SHF_EXECINSTR == 0`, not on `sh_type`. A `SHT_NOBITS` section with `SHF_EXECINSTR` (theoretically possible, never seen in practice) would project `sh_offset` as if it were backed by file content. Not a practical risk. |
| **Stale patch cache** | ✓ `PATCH_CACHE_VERSION` 1→2 forces re-scan. Confirmed by codex: _rust.abi3.so x18 patched 0→2736 after the bump. |

### 4.4 Recommendation: add a stripped-DSO safety net

The fallback `extract_code_ranges_from_memory` still silently returns `Vec::new()`
for non-header-aligned mappings of stripped DSOs. Consider a **tertiary fallback**:
if both extractors return empty AND the mapping is `PROT_EXEC`, fall back to
"whole mapping is code" (the coarsest strategy, `extract_code_ranges_via_phdrs`'s
last resort). This would over-approximate (potentially patching non-code data
that matches x18 bit patterns), but the existing `find_literal_pools` exclusion
and `references_x18` decoder already filter most false positives. A log message
("code-range extraction failed for exec mapping at X, falling back to whole-map")
would make this failure mode visible instead of silent.

---

## 5. The I-cache angle (user's question 3) — ANSWERED

**Question:** After fakelinux patches these instructions at load time, is an I-cache
invalidation performed before the guest executes them?

**Answer: Yes, in all three code-patching entry points — but the layering is fragile
and worth hardening.**

### 5.1 The three patching paths and their I-cache handling

| Path | Patch call | I-cache invalidation after patch | Verdict |
|---|---|---|---|
| **File-backed mmap** (main DSO load, `syscall.rs:2866–2869`) | `patch_new_code_file(result_addr, length, fd, offset)` | `sys_icache_invalidate(result_addr, length)` — covers the **entire mapping** | ✓ |
| **Sub-page file-backed MAP_FIXED** (`syscall.rs:2795–2798`) | `patch_new_code_file(addr, length, fd, offset)` | `sys_icache_invalidate(addr, length)` | ✓ |
| **Deferred mprotect→exec** (`thread.rs:1025–1028`) | `patch_new_code(aligned_addr, aligned_len)` | `sys_icache_invalidate(aligned_addr, aligned_len)` | ✓ |

In every case, the **caller** issues a covering `sys_icache_invalidate` over the
full mapping length AFTER `patch_new_code[_file]` returns, regardless of whether the
patcher hit the cache or did a full scan. The patch sites (where
`patch_x18_with_trampoline` writes `B <island>` into guest `.text`) are covered by
this outer invalidation. The island code is invalidated separately inside `emit()`
(`x18_trampoline.rs:323–324`).

### 5.2 Is first-execution ordering guaranteed?

**Yes.** The patching + I-cache invalidation happens **synchronously inside the
guest's `mmap` syscall** (emulated by `trap_handler` → `syscall::emulate` →
`do_mmap`). The guest's dynamic linker receives the mmap *result* only after
`do_mmap` returns. The linker then processes relocations and eventually calls into
the mapped code — by which point the D-cache has the patched instructions and the
I-cache has been invalidated. The first instruction fetch reads from the now-correct
D-cache. There is no window where stale I-cache lines for this mapping could exist
(the pages were freshly `mmap`'d anonymous + `pread`'d — never executed before).

### 5.3 The fragility I'd flag (not a live bug, but a maintenance hazard)

`patch_x18_with_trampoline` (`x18_trampoline.rs:451,464`) and
`patch_tpidr_with_trampoline` (`x18_trampoline.rs:512,521`) write to the patch site
**without a local `sys_icache_invalidate`**. Correctness currently depends on every
caller issuing a covering flush afterward. The `try_patch_from_cache` path
(`loader.rs:848`) flushes only `flush_all_islands()` (island code), leaning entirely
on the outer caller's `sys_icache_invalidate`. If a future code path calls
`patch_x18_with_trampoline` without an outer flush — for example, a new
runtime-patching entry point — the patch site could serve stale I-cache. **Recommend
adding a local `sys_icache_invalidate(pc_addr, 4)` inside the two `patch_*_with_trampoline`
functions** right after the `write(b)` call, making each function self-contained.
The cost is negligible (4-byte invalidation) and it eliminates the class of bug
entirely. The SIGBUS recovery path at `trap.rs:3715–3716` already does this
correctly — it's the right pattern to follow.

---

## 6. Falsifiable experiments (for the historical record)

Had the fix not arrived, these are the experiments I would have proposed, in order:

1. **(Decisive, would have found it directly)** Dump the patch-site coverage for
   every PROT_EXEC mapping at load time: for each `mmap(PROT_EXEC)`, log
   `(mapping_start, mapping_len, file_offset, code_ranges_found, x18_sites_patched)`.
   A mapping with `code_ranges=[]` and `x18_sites_patched=0` that the guest
   executes is the bug. Cost: 4 lines of logging in `patch_new_code_file`.

2. **Verify the EXECUTED binary, not a proxy.** At the corrupting store (P4/WATCH
   site), disassemble backward to find the containing DSO base (walk PT_LOAD
   ranges), then check whether the instruction's PC falls in a mapping the patcher
   scanned. `dladdr`-equivalent on the store PC → DSO path → re-run
   `extract_code_ranges` on that DSO's mapping → confirm ranges are empty.

3. **I-cache probe (would have been a negative result, but rules it out).** Insert
   a `udf #0xf002` immediately after a known-patched x18 instruction site; in the
   trap handler, read the instruction at the patched PC from D-cache and compare
   to what the CPU actually executed (esr_EL1 fetch decode). If D-cache says `B`
   but the CPU trapped on the original x18 instruction, it's an I-cache staleness
   bug. (This would have come back clean, but it's the only way to definitively
   close the I-cache angle.)

---

## 7. Lessons for the methodology (fold into §0 of the plan)

1. **A probe that returns "clean" is only valid for the subject it actually
   measured.** AES_X18_SCAN checked system libcrypto; the bug was in vendored
   _rust.abi3.so. Always record the DSO path / mapping address alongside any
   "verified" result.

2. **"Both modes fail ⟹ not X" requires that both modes actually reach X.**
   The NO_X18_TRAMP/tramp split only rules out the island vs. emulate distinction.
   It does NOT rule out "the patcher never covered this code." Coverage must be
   verified independently before mode-split logic is applied.

3. **The patch-cache is a silent failure multiplier.** A stale cache entry turns
   "we failed to scan" into "we scanned and found nothing" (try_patch_from_cache
   returns `true`). Cache version bumps are necessary but the cache should also
   record *how many* sites of each kind it found, and log a warning if a
   previously-populated cache for an exec mapping has zero x18 sites.

4. **Trust the determinism of AES.** "Correct inputs + correct code ⟹ wrong
   output" is impossible. If you reach this contradiction, an input is wrong that
   you are NOT measuring — by definition. Stop adding probes for the same category
   of state and look for a category you haven't instrumented (here: the patcher's
   coverage map).

5. **The self-constructed repro must match the target's binary path.** The scapy
   repro used system libcrypto (patched, clean-ish); the canonical repro used the
   vendored _rust.abi3.so (unpatched, corrupt). A repro that exercises a different
   binary than the target can produce a different (or no) bug.
