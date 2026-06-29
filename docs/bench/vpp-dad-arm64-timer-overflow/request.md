# Agent debugging benchmark — VPP IP6 DAD SIGABRT under fakelinux

## How to use this benchmark

The guest VPP tree is at `roots/ubuntu/root/vpp` (commit `2ac657d3c`, before the
fix `17ea0391b`). Run the IPv6 Duplicate Address Detection tests under fakelinux:

```
scripts/vpp-shell.sh 'make test-debug TEST=test_ip6_dad'
```

## Symptom

The **first** DAD test crashes VPP, and every later DAD test then ERRORs
(`VppDiedError: ... return code: 134` = 128 + SIGABRT). It is **100%
deterministic**. The VPP instance's `vpp_stderr.txt` (in
`roots/ubuntu/tmp/vpp-unittest-TestIP6DAD/`) shows:

```
/root/vpp/src/vppinfra/tw_timer_template.c:191 (timer_add)
   assertion `(u64) glacier_ring_offset < TW_SLOTS_PER_RING' fails
os_panic() called, aborting.
fakelinux: guest called abort (tgkill SIGABRT)
```

i.e. VPP's own timer wheel aborts while adding a timer whose interval is
absurdly large.

## The tempting (wrong) hypothesis

fakelinux is a Linux-syscall emulator on macOS; DAD is timer-driven
(RetransTimer / NS retransmissions). The obvious conclusion — and the one the
project's own plan wrote down — is a **fakelinux timer/signal-emulation bug**:
a `timerfd`/`itimer`/`clock_gettime` returning a wrong value, so VPP computes a
huge `expiry - now` and overflows the wheel. Chasing `src/timers.rs` /
`src/signal.rs` is the expected first move.

## Task

Find the true root cause of the abort and fix it so `test_ip6_dad` and
`test_ip6_dad_events` pass (looped K≥3, ideally K≥20, with 0 crashes).

Decide, with evidence, whether this is a **fakelinux bug** or something else —
and if something else, say exactly what and why fakelinux is (or isn't)
implicated. A fix that only papers over the symptom (e.g. catching SIGABRT) does
not count.
