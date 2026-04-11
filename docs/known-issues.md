# Known Issues and Future Fixes

Issues identified during code review. See docs/compatibility-roadmap.md for the
full plan to reach broader Linux compatibility.

## High Priority

### ~~Mutex in signal handler (signal.rs)~~ FIXED
Replaced with lock-free AtomicSigaction array. No more mutex in signal context.
Stress-tested with 5000 concurrent signal deliveries (test_signal_safety.c).

### ~~NEON/FP registers not saved in sigframe~~ FIXED
All 32 q0-q31 registers plus FPSR/FPCR saved/restored via macOS mcontext
in sigframe. Verified by test_neon_signal.c.

### ~~Fork/clone register restore incomplete~~ FIXED
Fork trampoline and clone_entry now restore ALL guest registers (x0-x15,
x17-x28, fp, lr, sp) via a naked asm function (restore_all_regs). x16/IP0
is used as the branch scratch register, which is acceptable per AAPCS.

### ~~posix_spawn in do_execve broke pipe inheritance~~ FIXED
Replaced posix_spawn with real execve, which preserves the child's exact
fd table (pipe redirections, dup2'd fds) across exec.

## Medium Priority

### SA_SIGINFO not supported
x1 (siginfo_t*) and x2 (ucontext_t*) are set to 0. SA_SIGINFO handlers that
dereference these will crash. Fix: build synthetic siginfo_t and ucontext_t.

### ~~SA_RESTART not implemented~~ FIXED
SA_RESTART is now handled in signal delivery.

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

## Working Features (Alpine rootfs)

The following Alpine Linux busybox commands work correctly with
`FAKELINUX_ROOT=./alpine-rootfs`:

- `echo hello`, `uname -a`, `date`, `id`, `wc -l /etc/passwd`
- `cat /etc/os-release`, `cat /etc/alpine-release`
- `ls /`, `ls -la /proc`
- `for i in 1 2 3; do echo $i; done` (shell loops)
- `date | cat` (pipe + fork)
- `echo $(date)` (command substitution / subshells)
- Fork + exec (TCP echo server/client test passes)
