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

### ~~FUTEX_WAIT_BITSET absolute timeout treated as relative~~ FIXED (5973fac)
`FUTEX_WAIT_BITSET` (used by Python 3.12's lock-with-timeout, i.e. every
`threading.Event.wait(t)` / `Condition.wait(t)`) carries an ABSOLUTE
CLOCK_MONOTONIC deadline, but parse_timeout treated all timeouts as relative —
so "wait 3s" became "wait ~seconds-since-boot" ≈ forever. Now converted to
relative by subtracting the current host clock; the timed wait is also
signal-interruptible. Was: the VPP test harness hung after a passing test class.

### ~~Process-shared futexes don't wake across fork~~ FIXED (1c5de0e)
A futex without `FUTEX_PRIVATE_FLAG` is process-shared: the wake can come from
another process (e.g. Python multiprocessing semaphores between a fork parent
and its `ProcessPoolExecutor` workers). The futex table is per-process, so a
remote `FUTEX_WAKE` never reached the waiter's condvar and it slept forever —
deadlocking any `multiprocessing.Pool` workload (e.g. the harness's post-run
`expand_ppp.py` hexdump expansion). Fix: the futex word lives in fork-shared
memory, so a shared-futex waiter polls `*uaddr` (10ms) and returns a
spurious-but-correct wake when a remote waker changes it; the guest re-checks.

## Medium Priority

### ~~SA_SIGINFO not supported~~ FIXED (87d26c2)
The rt_sigframe now carries a Linux siginfo_t (si_signo/si_code/si_addr) and
a ucontext_t prefix (uc_mcontext: fault_address, regs, sp, pc, pstate);
x1/x2 point at them. Was: VPP's SIGINT handler NULL-deref'd → signal storm.

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
