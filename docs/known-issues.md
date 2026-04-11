# Known Issues and Future Fixes

Issues identified during code review of Phase 1-6 implementation.

## High Priority

### Mutex in signal handler (signal.rs)
`GUEST_SIGACTIONS.lock()` in `signal_forwarder` is not async-signal-safe.
If a signal arrives while `do_rt_sigaction` holds the mutex, deadlock occurs.
Fix: replace with lock-free array of AtomicU64 pairs, or block signals around mutex hold.

### NEON/FP registers not saved in sigframe
The rt_sigframe only saves GPRs. Signal delivery during FP-heavy code will
corrupt NEON/FP state silently. Fix: save/restore 32x 128-bit NEON registers.

## Medium Priority

### SA_SIGINFO not supported
x1 (siginfo_t*) and x2 (ucontext_t*) are set to 0. SA_SIGINFO handlers that
dereference these will crash. Fix: build synthetic siginfo_t and ucontext_t.

### SA_RESTART not implemented
Interrupted syscalls are not restarted even if SA_RESTART is set.

### sigaction layout may differ
The sa_restorer field presence on aarch64 needs verification against musl.
Currently assumes {handler, flags, restorer, mask} but kernel struct may
omit restorer.

### tgkill SIGABRT always exits
Does not check for guest SIGABRT handler before calling _exit(134).

## Low Priority

### TOCTOU in deliver_pending_signals
Should use compare_exchange loop instead of separate load+clear.

### Early TPIDR return skips pending signal delivery
TPIDR fast paths in sigtrap_handler skip deliver_pending_to_guest.
Signals stay pending until next SVC trap (latency, not correctness).

### Sigframe trampoline signature is weak
Uses instruction bytes as magic; could collide with guest data.
Consider a random per-process cookie.
