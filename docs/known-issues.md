# Known Issues and Future Fixes

Issues identified during code review. See docs/compatibility-roadmap.md for the
full plan to reach broader Linux compatibility.

## High Priority

### ~~Mutex in signal handler (signal.rs)~~ FIXED
Replaced with lock-free AtomicSigaction array. No more mutex in signal context.

### ~~NEON/FP registers not saved in sigframe~~ FIXED
All 32 q0-q31 registers saved/restored via macOS mcontext in sigframe.

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
