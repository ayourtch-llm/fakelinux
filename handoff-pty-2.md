# pty-2 GCM corruption investigation — runbook handoff

Tacit knowledge from the pty-2 GCM-corruption probe session that isn't in
`docs/plans/2026-06-28-vpp-100pct-pass.md` or `docs/plans/baseline-0pt6-percent-findings.md`.
For a fresh investigator (possibly fresh-me) picking this up.

## 1. Repros (in tests/repro/)

All take `[N_iters] [psize_bytes] [interval_seconds]`. Default 8000/1970/0.0002.
Invoke via `scripts/vpp-shell.sh '/root/vpp/build-root/test/venv/bin/python3 /tmp/<file>.py [args]'`
(roots/ubuntu/tmp/ → /tmp/ inside guest; copy if not already present).

| File | What it isolates | Quick command |
|---|---|---|
| `gcm_signal_corruption.py` | Canonical: bytearray buffer in brk heap, `_ticks += 1` handler | `... gcm_signal_corruption.py 8000 1970 0.0002` |
| `gcm_signal_corruption_mmap.py` | 1.13 MB anon mmap buffer (so `FAKELINUX_WATCH` can target it); prints out_buf addr | `FAKELINUX_WATCH=1:123000:0 ... gcm_signal_corruption_mmap.py 8000 1970` |
| `gcm_pass_handler_verify.py` | N1: handler body is `_invoked.append(1)` (no global, no int alloc); reports invocation count | `... gcm_pass_handler_verify.py 8000 1970` |
| `gcm_sigign_partition.py` | SIG_IGN: signals fire but kernel drops them; `fwd_calls=0` expected | `... gcm_sigign_partition.py 8000 1970` |
| `gcm_fresh_buffer.py` | Fresh `bytearray` per iter; partitions inter-decrypt-stomp from in-decrypt corruption | `... gcm_fresh_buffer.py 80000 1970 0` |
| `run_linux_arm64.sh` | Hypothesis-4 partition: run the canonical repro on a native ARM64 Linux box | bash on aarch64 Linux |

### Canonical numbers to memorize (3-component decomposition, all at N=80,000)
```
canonical (forwarded signals):  bad = 2,735 / 80,000 = 3.42%   ticks ≈ 8,637
SIG_IGN (signals kernel-drops): bad =   410 / 80,000 = 0.51%   fwd_calls = 0
interval=0 (no itimer):         bad =   540 / 80,000 = 0.68%   fwd_calls = 0
FRESH + interval=0:             bad =   481 / 80,000 = 0.60%
NO_X18_TRAMP + interval=0:      bad =   477 / 80,000 = 0.60%
[native macOS, matched density: 0 / 8,000 ]
```

**Two-component decomposition**: ~0.6% signal-independent baseline + ~2.9pp
signal-forwarded delta. Each must be attacked separately; mechanisms differ.

## 2. Env-var matrix

| Env var | Effect | Output format |
|---|---|---|
| `FAKELINUX_TRAP_STATS=1` | Dumps `TRAP_STATS`, `TRAP_STATS2`, `ALTSTACK`, and `P4` lines at exit_group | Per-pid lines to stderr |
| `FAKELINUX_WATCH=<seq>:<len>:<off>` | All hex, no `0x`. Arms watch at the `seq`-th anon mmap of length `len`, on the 16 KB page containing byte `off`. Catches writes via mprotect+UDF-step. **single-threaded only** | `WATCH armed: addr=… page=…` and per-event `WATCH WRITE [addr] prev → cur by pc=…` (only when slot value changes) + on host-code disarm `WATCH HOST-CODE write!` |
| `FAKELINUX_WATCH_X27=1` | Multi-shot: on every signal_forwarder entry where `x27 ∈ [0x7_0000_0000, 0x8_0000_0000)` (openssl heap), arms WATCH on `x27+16` (= keystream slot). Rearms after disarm. | `WATCH armed (x27 trigger): addr=…` |
| `FAKELINUX_SIGTRACE=1` | Enables ring-buffer sigtrace + KS_PROBE + RK_PROBE + FWD_REG_PROBE (saved-vs-restored across forwarded round-trip) | `KS_STOMP`, `RK_STOMP`, `FWD_REG_DIVERGE` if any; counters in `TRAP_STATS2` |
| `FAKELINUX_CHECK_REGS=1` | REG_PROBE: snapshot x19..x28/fp/sp at trap_handler entry; Drop guard compares at every return. Legitimate-multi-reg branches (sigreturn, deliver_pending, build_sigframe) consume the snapshot before mutating. | `TRAP_REG_CHANGE` if any; counters `reg_checked` / `reg_hits` |
| `FAKELINUX_RESUME_PROBE=1` | Hijacks `mctx.pc` to a single `udf #0xf001` page; trap_handler compares post-restore mctx vs frame bytes | `RESUME_DIVERGE` if any; counters `RESUME_PROBE hits/divergences` |
| `FAKELINUX_NO_X18_TRAMP=1` | Disables trampolines globally; all x18 instructions fall back to SIGILL→emul. Use to test "is the trampoline-island execution the cause" | `tramp_ok=0 tramp_fb=0` in TRAP_STATS, `x18_fallback=N` |
| `FAKELINUX_NO_X18=1` | (Different!) Skips x18 patching entirely — original bytes execute natively. Likely-fatal on most binaries; use for sanity tests only | (no patch lines logged) |
| `FAKELINUX_BIG_ALTSTACK=1` | Bumps SA_ONSTACK altstack 128 KB → 1.28 MB. A/B test for "is signal_forwarder + Rust stack overflowing into kernel mctx". Verified: 3 KB used, 10× doesn't help | `altstack 0x…-0x…` log + `ALTSTACK lo=… min_sp=… used=… free_below=…` |
| `FAKELINUX_TRACE_X18_STORES=1` | Logs every x18-base store in the SIGILL emul path | `X18_STORE pc=… base=x… addr=… val=… size=… x18=…` |
| `FAKELINUX_AES_X18_SCAN=1` | One-shot scan at first WATCH WRITE event for openssl AES_encrypt x18 signatures (0x294144d2, 0x4a1200a5, 0xd3483cb2) in r-x mappings. Returned 0/0/0 → AES_encrypt IS patched | `AES_X18_SCAN findings: LDP_W18_W17=… EOR_W5_W18=… UBFM_X18_X5=… udf_markers_total=…` |
| `FAKELINUX_TRACE_X18=1` | Enables full x18 emul op trace (gated by `seq >= 13500` threshold inside trap_handler — would need code change to lower) | `X18_OP#seq pc=… instr=… x18=…→… x0=… x1=… x2=… x3=…` |

## 3. AES disasm facts (verified)

```
openssl AES_encrypt (libcrypto, _rust.abi3.so file offset 0x374a28):
  size 0x378 (222 instructions, 13 x18-touching)
  signature x18 instructions:
    +0x90   2a1203f2  MOV W18, W18
    +0xd0   b87278f3  LDR W19, [X7, W18, UXTW]
    +0xdc   b87178f2  LDR W18, [X7, W17, UXTW]
    +0xec   4a1200a5  EOR W5, W5, W18
    +0xfc   294144d2  LDP W18, W17, [X6, #8]   ← smoking-gun candidate
    +0x10c  4a120063  EOR W3, W3, W18
    +0x158  53187c72  UBFM W18, W3, #24, #31
    +0x1c8  b8727932  LDR W18, [X9, W18, UXTW]
    +0x1d8  4a160252  EOR W18, W18, W22
    +0x1e4  4a030243  EOR W3, W18, W3
    +0x1fc  d3483cb2  UBFM X18, X5, #8, #15
    +0x2c0  2a1203f2  MOV W18, W18
  prologue spills (P5): STP fp,lr,[sp,#-80]!; STP x19,x20,[sp,#16];
                        STP x21,x22,[sp,#32]; STP x23,x24,[sp,#48];
                        STR x25,[sp,#64]
  reads round keys from x2 (= caller's x21):
    +0x28  b940f04d   LDR W13, [X2, #240]   ← AES_KEY.rounds (proves x21=AES_KEY)

CTR-caller loop (in openssl CTR mode wrapper, watched STUR PC):
  -28  f9400b61   LDR  x1, [x27, #16]   ← loads keystream low-half
  -24  110004c6   ADD  …
  -20  5ac008c0   REV  X0
  -16  b9000f60   STR  W0, [X27, …]     ← counter increment
  -12  91004063   ADD  x3, x3, #16
  -8   f85f0060   LDUR x0, [x3, #-16]   ← load ciphertext
  -4   ca010000   EOR  x0, x0, x1       ← XOR ks
  0    f81f0260   STUR x0, [x19, #-16]  ← THE CORRUPTING STORE (faulting pc)
  +4   f85f8060   LDUR x0, [x3, #-8]    ← next half

  Register conventions at the corrupting STUR:
    x27 = counter/keystream buffer base (in Python heap, 0x7…)
    x21 = AES_KEY base (= x2 to AES_encrypt; same heap, ~+0x1c0 from x27)
    x22 = x27+16 = keystream output area  (= x1 to AES_encrypt)
    x20 = AES_encrypt function pointer (callee-saved, BLR x20 at -40)
    x19 = output buffer pointer (advances)
    x3  = ciphertext input pointer
    x0  = plaintext result (about to STUR)
    x1  = keystream low 8 bytes (just loaded from [x27+16])

Output buffer layout at WATCH hit (page = out_buf & ~0x3FFF):
  ALL stomps observed land within active region [out_buf, out_buf+psize).
  Tail (>1 MB past psize) has NEVER been stomped → not buffer overflow.
```

## 4. Probes still IN the working tree as diagnostics

All gated by env vars; **zero cost** when their gate is off. None reverted unless noted.

```
src/signal.rs:
  - FORWARDER_CALLS/DEFERRED/NESTED/MAX_DEPTH counters
  - KS_PROBE (FAKELINUX_SIGTRACE)
  - FWD_REG_PROBE incl cpsr/tpidr/fpsr/fpcr (FAKELINUX_SIGTRACE)
  - RK_PROBE — 240-byte round-key table snapshot/compare (FAKELINUX_SIGTRACE)
  - One-shot RK_FIRST log dumping x21 + first 32 bytes of round-key table

src/trap.rs:
  - exact-bounds host_anchor (FL_TEXT_START/END via dladdr+mach-o) — REAL FIX, kept
  - REG_PROBE (FAKELINUX_CHECK_REGS) with reg_probe_set_reason / reg_probe_check_now
  - RESUME_PROBE (FAKELINUX_RESUME_PROBE) — single-UDF page
  - WATCH_X27 (FAKELINUX_WATCH_X27) — multi-shot rearm
  - WATCH PC histogram (256-slot, with dladdr resolution) — dumps via dump_trap_stats
  - ALTSTACK lo/hi/min_sp probe; FAKELINUX_BIG_ALTSTACK switch
  - P4 a/b/c (round-key CRC, counter check, ptr-likeness) in watch_handle_step
  - P4 d/e (256-word code-integrity + 64-insn AES_encrypt routine snapshot)
  - P5 AES_SPILL dump (per-WATCH-hit [sp-80..sp) bytes, marked C/R)
  - AES_X18_SCAN (FAKELINUX_AES_X18_SCAN, one-shot at first WATCH WRITE)

src/x18_trampoline.rs:
  - test t1_trampoline_ldp_w18_w17_preserves_w17 — proves emit() correct for
    the LDP W18,W17,[X6,#8] smoking gun

REVERTED (don't look for):
  - Verbose dladdr-in-disarm dump (kept dladdr in histogram only)
  - WATCH WRITE x16/x17/x18 dump (was added then reverted unrebuilt)
```

## 5. Per-probe clean counts (decisive negatives)

For the bg run on `gcm_signal_corruption_mmap.py 40000 1970` unless noted:

```
KS_PROBE_CHECKED=669    KS_PROBE_STOMPS=0     keystream mem across round-trip clean
RK_PROBE_CHECKED=435    RK_PROBE_MISMATCHES=0 round-key table across round-trip clean
FWD_REG_PROBE: 949 round-trips, 0 mismatches across x[0..28]+fp+lr+sp+pc+cpsr+tpidr+fpsr+fpcr
REG_PROBE: 2,559 sync traps, 0 callee-saved mutations
RESUME_PROBE: 915 hits, 0 divergences (hw vs frame post-restore)
FORWARDER_NESTED=0  fwd_max_depth=0          (no nested forwarders in single-signal workload)
ALTSTACK: 3,216 bytes used of 128 KB; 10× altstack same bad rate
P4_RK_DIFFS=0  P4_CTR_MISMATCHES=0  P4_POINTER_LIKE_HITS=0  P4_CODE_DIFFS=0  P4_AES_FN_DIFFS=0
P5 AES_SPILL: per-x27 spill bytes identical between C and R hits
T1 (LDP W18,W17 trampoline): PASS (test t1_trampoline_ldp_w18_w17_preserves_w17)
AES_X18_SCAN: all 3 signatures found 0 times in r-x memory (= patched)
```

## 6. Best guess at where to look next, and why

**The bug's residual shape**: ~0.6% baseline, signal-independent,
fakelinux-specific, common to NEON-AES and scalar-AES paths, unchanged by
trampoline vs emul x18 handling, unchanged by buffer reuse. Per the
trichotomy this can only be wrong inputs / wrong code / wrong execution,
and we've ruled out the first two by direct measurement at the failing
store. So something architectural is being perturbed by fakelinux but
isn't visible to register-or-memory inspection at signal/syscall boundaries.

**My best single guess**: the corruption is in **a chunk of openssl-internal
state that's read DURING the AES round but not at the WATCH-trapped STUR**.
The probes verify register/memory at the STUR (post-AES-return) and at
signal boundaries — they don't catch mid-AES state. Specifically: openssl's
NEON-AES path holds the AES state in v0..v3 across many AESE/AESMC
instructions, and intermediate scratch state on the stack. **If macOS's
*synchronous* trap returns (e.g., the trap_handler exit from a sync SIGILL
trap during a non-x18 NEON sequence) silently fail to restore a NEON
register the same way they restore GPRs**, the NEON-AES round would
compute wrong output without any of the in-tree probes seeing it.

This is testable by adding a **NEON variant of FWD_REG_PROBE** that ALSO
snapshots v0..v31 — but for SYNC traps, not just forwarded signals. (The
existing FWD_REG_PROBE only covers async-signal forwarded round-trips;
REG_PROBE only covers GPRs+fp+sp for sync traps.) Concrete next probe:
extend `reg_probe_enter` to snapshot `mctx.ns.v[0..32]` and compare in
`reg_probe_check_exit`. With FAKELINUX_CHECK_REGS=1, this would catch any
NEON mutation across a sync trap (svc=2,980 sync traps per 80k iters →
~10 if NEON mutation rate were the 0.6% baseline).

**Second-best guess**: a **memory access through fakelinux's intercepted
syscall path** writes 1–2 bytes into openssl's internal state. The
candidates I'd check: `do_clock_gettime`, `do_getrandom`, `do_read` —
specifically whether they ever write beyond the requested buffer length
due to off-by-one or misaligned bookkeeping. Concrete check: enable
`FAKELINUX_TRACE_X18_STORES=1` and grep for any write address that lands
inside `[x27..x27+0x300)` (counter + keystream + round-key area) at any
point during interval=0 execution.

**Cheap probe I'd build first**: a **per-syscall WATCH** that arms WATCH
fresh after every SVC and disarms after a few non-faulting steps. With
~2,980 SVCs in 80k iters and the WATCH targeted at openssl's heap
neighborhood, any syscall handler that touches that region would surface
within a few minutes.

If both come back clean: the bug is genuinely below the level of in-tree
instrumentation (ETM/PMU territory) and parking is the right call. We're
not there yet — these two haven't been tried.

## 7. Quick how-to: spin up the same investigation cold

```bash
# 1. Build
cargo build --release

# 2. Baseline (with all probes off): canonical full forwarding
pkill -9 -f fakelinux 2>/dev/null; sleep 1
scripts/vpp-shell.sh '/root/vpp/build-root/test/venv/bin/python3 /tmp/gcm_signal_corruption.py 8000 1970'
# Expect ~270-300 / 8000

# 3. Confirm signal-INDEPENDENT baseline
scripts/vpp-shell.sh '/root/vpp/build-root/test/venv/bin/python3 /tmp/gcm_signal_corruption.py 8000 1970 0'
# Expect ~50-80 / 8000  (0.6-1% baseline at interval=0)

# 4. Catch the corrupting STUR with all diagnostics
FAKELINUX_WATCH=1:123000:0 FAKELINUX_SIGTRACE=1 FAKELINUX_TRAP_STATS=1 \
  scripts/vpp-shell.sh '/root/vpp/build-root/test/venv/bin/python3 /tmp/gcm_signal_corruption_mmap.py 40000 1970'
# Look for: WATCH WRITE lines (corrupting hits have non-0x5858 cur),
#          P4_* and P5_AES_SPILL dumps

# 5. Run the lib unit test that proves trampoline correctness for LDP W18,W17
cargo test --release --bin fakelinux t1_trampoline 2>&1 | tail -5
```
