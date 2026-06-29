# fakelinux — VPP `make test-debug` campaign handoff (2026-06-29)

Written by the autonomous campaign for a future-self with fresh context. Branch
`main`. Read top-to-bottom. **Commit hashes here are post-history-rewrite (valid).**

## North star
Drive VPP `make test-debug` (debug build, ~2498 tests) to 100% pass **under
fakelinux** (ARM64-Linux-syscall emulator on macOS). VPP tree lives at
`roots/ubuntu/root/vpp` (its own gitignored FDio/vpp checkout, currently at
`2ac657d3c` + our local fix `17ea0391b`).

## TL;DR current state (2026-06-29 ~21:25) — full run FINISHED (cut short by cluster D)
- The full `make test-debug` ENDED early: `DONE_RC=2`, executed **1552/2498**, final
  **1210 OK / 3 FAIL / 1 ERROR / 338 SKIP**. Log: `/tmp/full_testdebug.log`.
- **Cluster D reproduced** and is what terminated the run. Chain:
  1. `TestCrypto` "Crypto+HMAC Performance Tests" (asf/test_crypto.py:47) ran
     `self.vapi.cli(cmd)` -> `cli_inband` with a LARGE reply ->
     **`VPPIOError(2, "VPP API client: read failed")`** (the AF_UNIX sockbuf bug —
     macOS's small SO_RCVBUF starves a big API response; see memory
     `project_afunix_sockbuf`, partially fixed before for TestVpeApi log_dump).
  2. Cascaded into the harness: `stdouterr_reader_wrapper` (managed-queue reader
     thread) got **EOFError**, plus **BrokenPipeError** on send.
  3. Run limped on (Bihash passed) then died fatally at `run_tests.py:1422` ->
     terminated; the ~946 tests after Bihash never ran.
- So cluster D's trigger HERE is **`TestCrypto`, NOT DS-Lite**, and the root is a
  **large-API-reply read failure**, NOT a fork race (consistent with my
  `mp_stress.py` repro NOT reproducing it). The harness EOFError/BrokenPipe is a
  CONSEQUENCE of the TestCrypto API failure, not an independent manager bug.
- Otherwise everything green: only the 3 known VCL `private-rx-mqs` FAILs. IPsec
  163 OK/0 FAIL. No teardown wedge (futex livelock looks clear). The debug suite
  is SLOW (~110min got to ~56%; openssl-IPsec at ~22s/test was the bottleneck).
- **The 4.5-min monitoring wake-loop is STOPPED** per user request.

### NEXT — cluster D FIXED 2026-06-30 (root cause was a timeout, NOT the recv path)
DONE. Reproduced `TestCrypto.test_crypto_perf` in isolation; bumping
`vapi_response_timeout` 5→60 made it PASS in 44s, proving the failure is VPP
compute slowness (debug build + emulation), not an AF_UNIX large-reply/sockbuf
overflow. Fix landed: per-class `cls.vapi_response_timeout = 120` in
`TestCrypto.setUpClass` (VPP `97b84156d`). Verified 3/3 OK. Do NOT chase the
src/net.rs recv path for this — the reply was small and timely all along.

Next candidates (pick one):
1. **Run the full suite again** to get the authoritative post-fix inventory and
   confirm the manager no longer dies (~110min; nohup-detach + DONE_RC marker).
2. **VCL private-rx-mqs** (cluster C) — the lone remaining functional failure
   cluster (3 tests). See cluster-C row.
3. Defensive harness hardening so one VPPIOError can't terminate the whole run.
4. QUEUED follow-up #1 (env::var_os-per-close, small/safe).

## Cluster status (plan: docs/plans/2026-06-28-vpp-100pct-pass.md §§A–E)
| Cluster | State |
|---|---|
| **A — IPsec/GCM corruption** (~110 fails) | FIXED. Root cause was the x18/DSO bug (commit `f9f2f60`, pre-session). This run: **163 IPsec OK / 0 FAIL**, all GCM/CBC/CTR/GMAC × openssl/async/native/ipsecmb. |
| **B — IP6 DAD SIGABRT** (13 ERRORs) | FIXED — and it was NOT a fakelinux bug. VPP-on-aarch64 bug: DAD process passed `1e70` "sleep forever" -> `(u64)(1e70*1e5)` saturates `fcvtzu`->U64_MAX -> timer wheel `interval+current_tick` wraps u64 -> bypasses overflow guard -> `ASSERT(glacier_ring_offset<TW_SLOTS_PER_RING)`->os_panic. x86 cast yields ~9.2e18 (no wrap) so x86 CI missed it. Fix: finite sentinel `1e8` in `roots/ubuntu/root/vpp/src/vnet/ip6-nd/ip6_dad.c` (VPP commit `17ea0391b`; mirror `docs/vpp-patches/0001-ip6-nd-fix-DAD-timer-wheel-overflow-aarch64.patch`). Verified 15/15 OK x3 runs. |
| **C — GSO, IKEv2** | now PASS (were stale cluster-A collateral). |
| **C — 3x VCL InterruptMode/BAPI** | OPEN, deferred (isolated, don't block suite). `test_vcl.VCLThruHostStackEchoInterruptMode`, `...TLSInterruptMode`, `VCLCutThruTestCaseBAPI`. All "Client worker did not finish in 20s". Differ from PASSING base classes only by `use-private-rx-mqs`. Live `sample` of both `vperf_client`+`vperf_server` shows them spinning in `clock_nanosleep` poll loops -> session connect/accept handshake never progresses (no crash, no fakelinux error). Suspect: private-rx-MQ eventfd notification lost -> vppcom falls back to slow polling, OR private shared-segment incoherence. NOT yet root-caused. |
| **D — harness multiprocessing-manager death** | **FIXED 2026-06-30 — and the "large reply / AF_UNIX sockbuf" theory was WRONG.** Reproduced `TestCrypto.test_crypto_perf` `VPPIOError(2,"read failed")` in isolation. Root cause: NOT a buffer/recv bug — `test crypto perf` runs a real AES/SHA benchmark (512 buf × 200 rounds × 6 combos) inside VPP; on debug+aarch64-emulation one CLI takes ~7s, full sweep ~44s, blowing the default `vapi_response_timeout = 5` (asfframework.py:302). The reply is small/timely; only VPP compute is slow (same family as cluster B). Fix: per-class `cls.vapi_response_timeout = 120` in `TestCrypto.setUpClass` (VPP `97b84156d`; mirror `docs/vpp-patches/0002-...patch`), mirroring the existing `TestBihash` (=200) idiom. Verified 3/3 OK. The harness EOFError/BrokenPipe manager death was a CONSEQUENCE of this one VPPIOError; with the trigger gone the full run shouldn't hit it. Deferred (not done): defensively make the manager survive a single test's VPPIOError without killing the suite. |
| **futex teardown livelock** | NOT wedged so far. Graded-backoff fix already in `src/thread.rs` (`futex_spin_backoff_us`) from a prior session; this run hasn't wedged in teardown. Verifies on completion. |
| **E — full rerun & close-out** | IN PROGRESS = the running full suite. On completion, take the authoritative failure inventory. |

## Commits this session (fakelinux repo, branch `main`)
- `a79bfb7` apt SHA-256 K-table fix (workaround: find_crypto_const_tables signature guard)
- `ffa181a` **generic** function-level code ranges for the file-mapping patch path (FDE ∪ .dynsym/.symtab STT_FUNC; `extract_code_ranges_from_file_precise` in src/loader.rs; PATCH_CACHE_VERSION 2->3). The principled fix; signature guard is now just a fallback backstop.
- `190ed5d` gate `__TEXT bounds`/`altstack`/`runtime patch` banners behind `FAKELINUX_VERBOSE` (diag::verbose())
- `bd99f8f` bench: record live test_ipsec_esp confirmation
- `f80be5f` docs/bench for cluster B (vpp-dad-arm64-timer-overflow)
- `8f35b51` docs: cluster C triage
- VPP repo `17ea0391b` ip6-nd DAD fix (in roots/ubuntu/root/vpp)

### apt SHA-256 fix context (a79bfb7 + ffa181a)
Regression from `f9f2f60`. apt hashes via **libgcrypt** (not libapt-pkg/OpenSSL — that misattribution was the bench's trap). libgcrypt's ARMv8-CE SHA-256 K-table is inline in `.text` with NO `.eh_frame` FDE; 9 of 64 K-constants decode as x18-referencing instrs; the section-mode file-path patcher overwrote them -> corrupt hash. Fix gives the file path the same FDE precision the memory path had. Verified: apt-get update 0 mismatches, gcm_evp_fixed bad=0, smoke PASS.

## Benchmarks added (docs/bench/)
- `vpp-dad-arm64-timer-overflow/` — "emulator vs faithfully-exposed guest bug" (cluster B). SOLVED.
- `apt-sha256-hash-regression/` — SOLVED (root cause + both fix layers + live VPP confirmation).

## Test-framework CPU profiling (user asked; findings)
- Per-test CPU is the **Python test process (~99%)**, NOT VPP (2.6%). So VPP-code changes won't speed tests; the harness is the lever.
- Ruled out: GIL contention (blocked bg threads cost 0.98x — measured via `roots/ubuntu/tmp/gil_repro.py`), scapy crypto (fast ~1ms/pkt raw), vppctl forks (get_vpp_time uses binary-API). macOS `sample` counts BLOCKED threads, so big ppoll/futex sample counts were just parked papi `message_thread`/pump threads — misleading.
- Real driver: main thread in pure-Python (scapy packet build/copy/dissect — ~7900 Py calls/packet; `copy_field_value` 72800x for 400 pkts), amplified by fakelinux's per-syscall/per-bytecode SIGILL trap (~5-10us vs ~100ns). Same shape is slow on native too (user confirmed), fakelinux magnifies it.
- Levers: reduce scapy packet volume / cache expected packets / compare bytes not re-dissect; fewer API/poll round-trips.
- Repros: `roots/ubuntu/tmp/{scapy_esp_prof.py, scapy_esp_time.py, gil_repro.py, mp_stress.py}`.

## QUEUED follow-ups (post-run)
1. **`env::var_os`-per-close fix**: `wake_socket_before_close` (src/syscall.rs ~line 1120) reads `std::env::var_os("FAKELINUX_TRACE_SOCKET_CLOSE")` on EVERY close(), in trap (signal) context -> latent env-lock deadlock (violates the init_trace_flags rule) + hot-path cost. Cache it at init like other trace flags. Small, safe.
2. **Real-test cProfile** of one IPsec test for the exact hot Python loop (deferred to avoid perturbing the full run).
3. **VCL private-rx-mqs** root cause (cluster C) — lone remaining functional failure cluster. Start: trace the private rx MQ eventfd creation/SCM_RIGHTS passing + whether the app's epoll/poll on it ever fires; compare to the passing poll-main path.
4. Optionally a per-syscall-number histogram in fakelinux for better profiling.

## Key commands / gotchas
- Run suite: `scripts/vpp-shell.sh 'make test-debug TEST=<filter>'`. Filter: bare=file (`TEST=bfd`), class=`file.Class`, method=`file.Class.method`. asf/ tests by basename. Empty=full (2498).
- **Always `pkill -9 -f fakelinux` before launching a run.** Long runs: nohup-detach + a `DONE_RC=` log marker (ground truth). Usage outages kill wakeups.
- Rebuild fakelinux: `cargo build --release` (-> target/release/fakelinux; scripts use it). Rebuild VPP debug (after a VPP source edit): `scripts/vpp-shell.sh 'make build'` (incremental). Do NOT rebuild fakelinux mid-full-run (new test procs would use a different binary).
- Guest `ps` shows the fakelinux-wrapped process names. Host-side, match workers with `pgrep -f 'bin/vperf_client'` etc.; `sample <pid> N -file X` for native+fakelinux stacks (guest Python frames show as `???`).
- Each `vpp-shell.sh` invocation is a SEPARATE fakelinux container (re-rooted AF_UNIX) -> can't vppctl another container's VPP. Use `roots/ubuntu/tmp/run_both.sh` to run a client+VPP in one container.
- vppctl path: `roots/ubuntu/root/vpp/build-root/install-vpp_debug-native/vpp/bin/vppctl -s <runtime-dir>/cli.sock '<cmd>'`.
- Test artifacts (wiped on cleanup, symlinked on fail): `roots/ubuntu/tmp/vpp-unittest-<Class>/` (log.txt, vpp_stderr.txt). `/tmp/vpp-failed-unittests/`.

## Memory pointers (auto-memory)
See MEMORY.md. New this session: `project_apt_sha256_ktable`, `project_vpp_arm64_float_saturation` (the fcvtzu-saturation PATTERN — check it first when a VPP test aborts VPP with an ASSERT/rc134 under fakelinux; often a guest bug, not emulation).

## How to resume
1. Check the full run: `grep DONE_RC= /tmp/full_testdebug.log` and `/tmp/full_verdict.txt`.
   - COMPLETED -> tally final OK/FAIL/ERROR, list non-VCL failures = authoritative inventory; pick next cluster; fix; re-run.
   - STALLED (no DONE_RC, idle procs) -> futex teardown livelock: src/thread.rs futex_wait/futex_spin_backoff_us.
   - EOFError/BrokenPipe in log -> cluster D (manager death) reproduced: compare vs mp_stress.py.
2. If all green except the 3 VCL -> do the post-run queue (env::var_os fix, then VCL root cause).
