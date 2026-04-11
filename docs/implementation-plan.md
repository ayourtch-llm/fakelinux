# fakelinux Implementation Plan

## Development Process

Each phase follows **red-green TDD** in a dedicated tttt terminal session:

1. **Red**: Write failing test(s) for the feature — a small C program cross-compiled via Docker that exercises the syscall(s), run under fakelinux, expected to fail (ENOSYS, crash, wrong output)
2. **Green**: Implement the minimum code to make the test(s) pass
3. **Refactor**: Clean up if needed, ensure no regressions (run all prior tests)
4. **Commit**: Once tests pass, commit with a descriptive message
5. **Review**: A separate Opus agent reviews the commit for correctness, edge cases, security, and macOS gotchas

Tests live in `tests/` as C source files. A `tests/run_tests.sh` harness cross-compiles them in Docker and runs each under fakelinux, checking exit codes and stdout.

---

## Dependency Graph

```
Phase 0 (foundation)
  |---> Phase 2 (polling) ---> Phase 3 (networking)
  \---> Phase 4 (dynamic linking) ---> Phase 5 (threads)
Phase 1 (signals) ---> Phase 3 (networking, needs SIGPIPE)
                  \--> Phase 5 (threads, per-thread signal mask)
Phase 4 + Phase 6 (rootfs) = full Linux distro support
```

---

## Phase 0: Foundation (Small, 1-2 days)

### Goal
Add missing syscalls that glibc and the dynamic linker depend on, plus a test harness.

### Syscalls to implement
- `SYS_STATX` (291) — glibc 2.35+ prefers over fstat/newfstatat. Call macOS `fstatat`, translate result into Linux `struct statx`.
- `SYS_READV` (65) — read-side counterpart of writev.
- `SYS_PREAD64` (67) — positional read, needed by dynamic linker.
- `SYS_PWRITE64` (68) — positional write.

### Deliverables
- [ ] `tests/run_tests.sh` — test harness (Docker cross-compile + run under fakelinux)
- [ ] `tests/test_statx.c` — test program using statx syscall
- [ ] `tests/test_readv.c` — test program using readv
- [ ] `tests/test_pread.c` — test program using pread64/pwrite64
- [ ] Implement SYS_STATX in `syscall.rs` + `translate.rs`
- [ ] Implement SYS_READV in `syscall.rs`
- [ ] Implement SYS_PREAD64/PWRITE64 in `syscall.rs`
- [ ] All existing busybox tests still pass (regression check)

### Files to modify
- `src/linux.rs` — syscall number constants
- `src/syscall.rs` — dispatch cases
- `src/translate.rs` — struct statx translation

---

## Phase 1: Guest Signal Delivery (Large, 3-5 days)

### Goal
Enable the guest to register and receive signals (SIGCHLD, SIGALRM, SIGPIPE, SIGUSR1, etc.) with correct Linux ABI semantics.

### What to implement
- Build Linux `rt_sigframe` on guest stack when forwarding a signal
- Real `rt_sigreturn` (139) — restore guest regs from signal frame
- Real `rt_sigprocmask` (135) — track per-process guest signal mask
- `sigaltstack` (132) — guest alternate signal stack
- `kill` (129), `tkill` (130)
- Pending-signal queue for signals arriving during syscall emulation
- `SA_RESTART` semantics (return -EINTR or restart)

### Key technical challenges
- Signal-within-signal: forwarding handler must not interfere with SIGTRAP
- Linux vs macOS `struct ucontext` layout — must synthesize Linux layout
- TPIDR save/restore in signal frame
- `rt_sigreturn` trampoline must use BRK (SVC is patched)

### Tests
- [ ] `tests/test_sigalrm.c` — register SIGALRM handler, call alarm(1), verify handler runs
- [ ] `tests/test_sigchld.c` — fork, child exits, verify SIGCHLD handler fires
- [ ] `tests/test_sigprocmask.c` — block/unblock SIGUSR1, send to self, verify delivery order
- [ ] `tests/test_sigaltstack.c` — install alt stack, verify handler runs on it

### Files to modify
- `src/signal.rs` — major expansion: signal frame, rt_sigreturn, pending queue
- `src/trap.rs` — forward non-SIGTRAP signals, signal queue delivery
- `src/syscall.rs` — kill, tkill, sigaltstack, fix rt_sigreturn
- `src/linux.rs` — signal frame layout constants

---

## Phase 2: Polling and Event Syscalls (Medium, 2-3 days)

### Goal
Enable event-driven programs. Prerequisite for practical networking.

### Syscalls to implement
- `ppoll` (73) — translate pollfd flags, call macOS poll with timeout conversion
- `pselect6` (72) — translate and call macOS pselect
- `epoll_create1` (20), `epoll_ctl` (21), `epoll_wait` (22) — emulate via kqueue
- `eventfd2` (19) — emulate with pipe + in-process counter
- `timerfd_create` (85), `timerfd_settime` (86), `timerfd_gettime` (87) — kqueue timer or background thread

### Key technical challenges
- epoll-to-kqueue translation: EPOLLET -> EV_CLEAR, EPOLLONESHOT -> EV_ONESHOT
- epoll_ctl EPOLL_CTL_MOD: kqueue has no modify, must delete+re-add
- eventfd semantics: EFD_SEMAPHORE mode vs default mode
- macOS `poll` lacks ppoll's atomic signal mask; use sigprocmask+poll+restore

### Tests
- [ ] `tests/test_ppoll.c` — poll stdin with timeout, verify timeout returns 0
- [ ] `tests/test_epoll.c` — create epoll, add pipe, write, verify epoll_wait returns readable
- [ ] `tests/test_eventfd.c` — write/read eventfd counter, verify values
- [ ] `tests/test_timerfd.c` — create timerfd, set 100ms, poll, verify readable

### Files to modify/create
- `src/syscall.rs` — dispatch
- `src/linux.rs` — epoll/eventfd constants
- `src/epoll.rs` (new) — epoll-to-kqueue translation
- `src/eventfd.rs` (new) — eventfd emulation

---

## Phase 3: Networking (Medium, 3-4 days)

### Goal
TCP/UDP/Unix socket support for static binaries.

### Syscalls to implement
- `socket` (198), `connect` (203), `bind` (200), `listen` (201), `accept4` (242)
- `sendto` (206), `recvfrom` (207), `sendmsg` (211), `recvmsg` (212)
- `setsockopt` (208), `getsockopt` (209)
- `getpeername` (205), `getsockname` (204)
- `shutdown` (210)

### Key technical challenges
- `SOCK_NONBLOCK`/`SOCK_CLOEXEC` encoded in type arg on Linux, need fcntl on macOS
- `accept4` -> `accept` + fcntl (macOS lacks accept4)
- `sockaddr_un` sun_len field (macOS requires it, Linux doesn't have it)
- `SO_NOSIGPIPE` on every socket or handle SIGPIPE (depends on Phase 1)

### Tests
- [ ] `tests/test_tcp_echo.c` — TCP loopback echo (server+client in fork)
- [ ] `tests/test_udp.c` — UDP sendto/recvfrom loopback
- [ ] `tests/test_unix_socket.c` — Unix domain socket pair
- [ ] `tests/test_socket_nonblock.c` — SOCK_NONBLOCK flag handling

### Files to modify/create
- `src/syscall.rs` — dispatch
- `src/linux.rs` — networking constants
- `src/translate.rs` — socket flag translation, sockaddr_un
- `src/net.rs` (new) — networking syscall implementations

---

## Phase 4: Dynamic Linking (Large, 5-7 days)

### Goal
Load and run dynamically-linked aarch64 Linux binaries using ld-linux + glibc from sysroot.

### What to implement
- Complete PT_INTERP loading (scaffolded in loader.rs)
- R_AARCH64_GLOB_DAT and JUMP_SLOT relocations (currently skipped)
- Lazy SVC/TPIDR patching: when mprotect adds PROT_EXEC, scan + patch new code
- Path translation via FAKELINUX_SYSROOT in openat for /lib, /usr/lib, /etc/ld.so.cache
- Make TPIDR side-table appendable at runtime (currently frozen)
- New syscalls: `membarrier` (283), `fstatfs` (44)
- Mask MAP_DENYWRITE in mmap, emulate O_PATH via O_RDONLY

### Key technical challenges
- Every .so loaded by ld.so needs SVC-to-BRK and TPIDR patching
- Approach: hook do_mmap/do_mprotect — when PROT_EXEC appears, scan and patch
- TPIDR_PATCHES must become concurrent (RwLock or append-only vec)
- 16KB page alignment vs 4KB-aligned .so segments
- /proc/self/maps must stay accurate as ld.so mmaps libraries

### Tests
- [ ] `tests/test_hello_dynamic.c` — dynamically-linked hello world (gcc without -static)
- [ ] `tests/test_dlopen.c` — dlopen/dlsym a shared library
- [ ] Verify: run /bin/ls from Ubuntu aarch64 rootfs with FAKELINUX_SYSROOT

### Files to modify
- `src/loader.rs` — PT_INTERP, GLOB_DAT/JUMP_SLOT, runtime-appendable TPIDR table
- `src/syscall.rs` — path prefix in do_openat, exec-page patching hook in do_mmap/do_mprotect
- `src/translate.rs` — O_PATH, MAP_DENYWRITE
- `src/procfs.rs` — keep mappings in sync with dynamic mmap

---

## Phase 5: Thread Support (Large, 5-7 days)

### Goal
Full CLONE_THREAD support for multithreaded programs.

### What to implement
- Per-thread TPIDR: pthread TLS key instead of global AtomicU64
- Per-thread TID: TLS instead of global CURRENT_TID
- Per-thread sigaltstack: each pthread gets its own signal stack
- Fix clone_entry: save full guest regs, restore with x0=0 + child_stack
- Futex: timeout handling, WAIT_BITSET/WAKE_BITSET, CMP_REQUEUE
- CLONE_CHILD_CLEARTID: write 0 + futex wake on thread exit
- `clone3` (435) implementation

### Key technical challenges
- Per-thread TPIDR lookup in SIGTRAP handler (use macOS TPIDR or pthread_self as key)
- Signal delivery to specific threads (tgkill tid-to-pthread mapping)
- Thread exit cleanup: CLEARTID futex, sigaltstack, per-thread state
- macOS: sigaltstack is NOT inherited by new pthreads

### Tests
- [ ] `tests/test_threads.c` — pthread_create/join with shared counter + mutex
- [ ] `tests/test_condvar.c` — pthread_cond_wait/signal
- [ ] `tests/test_thread_tls.c` — each thread has its own TLS pointer
- [ ] `tests/test_many_threads.c` — stress test: create 100 threads

### Files to modify
- `src/thread.rs` — major rewrite: per-thread state, clone_entry, futex enhancements
- `src/trap.rs` — per-thread TPIDR lookup, per-thread sigaltstack
- `src/signal.rs` — per-thread signal masks, thread-directed delivery
- `src/syscall.rs` — clone3

---

## Phase 6: Container / Rootfs Support (Medium, 3-4 days)

### Goal
Run full Linux distributions (Alpine, Ubuntu) under fakelinux with path isolation.

### What to implement
- Path translation layer: FAKELINUX_ROOT prefix for all file syscalls
- `chroot` emulation with virtual root tracking
- Expanded /proc: /proc/cpuinfo, /proc/sys/kernel/osrelease, /proc/self/mountinfo
- /dev passthrough: /dev/null, /dev/zero, /dev/urandom -> macOS equivalents
- `statfs`/`fstatfs` (43/44) returning Linux-like filesystem info

### Key technical challenges
- Path translation must be efficient (every openat call)
- Symlinks inside rootfs pointing to absolute paths need re-translation
- Relative paths + AT_FDCWD: only absolute paths get prefixed
- execve path translation through rootfs prefix

### Tests
- [ ] `tests/test_chroot.c` — chroot into a minimal rootfs, verify path isolation
- [ ] `tests/test_dev_null.c` — open /dev/null, /dev/zero, /dev/urandom
- [ ] `tests/test_proc_cpuinfo.c` — read /proc/cpuinfo, verify aarch64 content
- [ ] Integration: run Alpine rootfs shell with FAKELINUX_ROOT

### Files to modify/create
- `src/rootfs.rs` (new) — path translation, chroot state
- `src/syscall.rs` — wrap file syscalls through path translator
- `src/procfs.rs` — new /proc entries
