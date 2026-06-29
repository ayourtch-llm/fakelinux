# Expected response — VPP IP6 DAD SIGABRT under fakelinux

> **STATUS: SOLVED 2026-06-29** (VPP fix `17ea0391b`; patch mirrored at
> `docs/vpp-patches/0001-ip6-nd-fix-DAD-timer-wheel-overflow-aarch64.patch`).

## Root cause — a VPP-on-aarch64 bug, NOT fakelinux

It is **not** a clock/timer-emulation bug. The decisive clock value is a
**hard-coded constant**, and the bug is a platform-dependent float→int
conversion in VPP's own code that fakelinux faithfully reproduces.

1. The DAD process (`src/vnet/ip6-nd/ip6_dad.c`, VPP commit `1f7348b6d`) uses
   `next_timeout = 1e70` as a "sleep forever" timeout when no address is
   tentative, and passes it to `vlib_process_wait_for_event_or_clock(vm, dt)`.
2. That function computes `p->resume_clock_interval = dt * VLIB_TW_TICKS_PER_SECOND`
   (`1e5`) and stores it in a **`u64`** (`node_funcs.h`). So the value is
   `(u64)(1e70 * 1e5) = (u64) 1e75`. `main.c:1223` feeds it straight to
   `vlib_tw_timer_start` with **no clamp**.
3. **Float→u64 of an out-of-range value is architecture-dependent:**
   - **aarch64** `fcvtzu` **saturates to `U64_MAX`** (`0xFFFF…FFFF`).
   - **x86-64** yields `~0x8000000000000000` (~9.2e18).
4. In `timer_add` (`tw_timer_template.c`), the wheel guards "too far in the
   future" with
   `interval_plus_time_to_wrap = interval + (current_tick & triple_wrap_mask)`
   and, if `>= 1 << (3*TW_RING_SHIFT)`, parks the timer on the overflow vector
   and returns. With `interval = U64_MAX`, `interval + current_tick`
   **wraps u64 back to a tiny value**, so the guard is **false**, execution
   falls through to `glacier_ring_offset = interval >> (2*TW_RING_SHIFT)` which
   is enormous, and `ASSERT(glacier_ring_offset < TW_SLOTS_PER_RING)` fails →
   `os_panic` → abort. On x86 the value ~9.2e18 does **not** wrap, the guard is
   true, and the timer parks cleanly → no crash. Hence **arm64-only**, missed by
   VPP's x86 CI.
5. fakelinux is uninvolved: `fcvtzu` is a plain FP instruction that runs
   natively on the host Apple CPU — exactly as it would on native arm64 Linux.
   The same VPP build would abort on a native arm64 box.

## The load-bearing reasoning step

Resist "DAD is timer-driven → fakelinux clock bug." The interval that overflows
traces back to a **literal `1e70`**, not to any emulated clock value, and the
crash is a **u64 wraparound that only manifests under aarch64 float saturation**.
An agent must (a) read the assert's `interval`/offset math, (b) trace `interval`
back to the constant, and (c) recognize the arch-dependent `fcvtzu` saturation —
then conclude the emulator is faithful and the guest code is at fault.

## Fix

`ip6_dad.c`: replace the `1e70` sentinel with a finite far-future value
(`IP6_DAD_SLEEP_FOREVER = 1e8` ≈ 3 years). It is effectively infinite for an
event-driven process (woken immediately by START / NA_RECEIVED events) yet keeps
`dt * 1e5` (`1e13`) well inside u64 and on the wheel's overflow-vector path.

Verified: `test_ip6_dad` + `test_ip6_dad_events` → 15/15 OK per run, 3 runs, 0
aborts (was 100% deterministic crash).

A defensible alternative/general fix is to **clamp in VPP's vlib layer**
(`vlib_tw_timer_start` or where `resume_clock_interval` is computed) so any
oversized suspend is capped — that fixes the whole class, at the cost of a much
larger rebuild. Either is acceptable for full credit; the DAD-local fix is
minimal.

## Grading rubric

- **Full credit:** identifies the `1e70 → fcvtzu-saturate → u64-wrap → wheel
  assert` chain, states it is a VPP-arm64 bug (not fakelinux) with the x86-vs-arm
  contrast, and lands a fix taking the test to 0 crashes.
- **Strong partial:** localizes the overflow to the `1e70` sentinel + unclamped
  `resume_clock_interval` and fixes it, without the x86/arm float-saturation
  contrast.
- **Partial:** correctly rules out fakelinux's clock/timer emulation and shows
  the interval comes from a constant, without the full wheel/wrap mechanism.
- **Weak:** blames fakelinux `timers.rs`/`signal.rs`, "fixes" by trapping
  SIGABRT, or disables the test.
