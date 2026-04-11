# Compatibility Roadmap

Path from current state to full Linux userspace compatibility.
Current: ~110 syscalls, basic Alpine rootfs shell works.
Target: run apk, build tools, daemons — full unshare -r equivalent.

## Phase 7: Signal safety and correctness

### 7a: Fix signal mutex deadlock (HIGH — silent bug)
`GUEST_SIGACTIONS.lock()` in `signal_forwarder` is not async-signal-safe.
Replace with a lock-free array: `[AtomicU64; 65]` pairs for handler+flags,
or block all signals around the mutex hold in `do_rt_sigaction`.

### 7b: SA_SIGINFO support
Build synthetic `siginfo_t` and `ucontext_t` on the sigframe so SA_SIGINFO
handlers can dereference x1/x2 without crashing. Needed by musl internals.

### 7c: SA_RESTART semantics
When a syscall is interrupted by a signal with SA_RESTART, restart it
instead of returning -EINTR. Affects read, write, wait4, accept, etc.

### 7d: Guest sigaltstack syscall (132)
Track per-thread guest alternate signal stack. When delivering a signal
with SA_ONSTACK, build the sigframe on the guest's alt stack instead of
the regular guest stack.

## Phase 8: File operations for package managers

### 8a: symlinkat (36) / readlinkat fix
Create symbolic links. Required by tar, apk, and /etc setup.

### 8b: linkat (37)
Create hard links. Required by tar --hard-dereference, cp -l.

### 8c: flock (32)
File locking via flock(). Required by apk, dpkg, and any lockfile.
Delegate to macOS flock() with flag translation.

### 8d: utimensat (88)
Set file timestamps with nanosecond precision. Required by tar, touch,
cp -p, make, and most build tools.

### 8e: ftruncate (46) / fallocate (47)
Truncate/extend files. Used by databases, log rotation, dd.

### 8f: lstat via fstatat
Ensure AT_SYMLINK_NOFOLLOW works in newfstatat for lstat semantics.

## Phase 9: Terminal and ioctl support

### 9a: Terminal ioctls
TCGETS/TCSETS (0x5401/0x5402) — terminal attribute get/set. Required by
any interactive program. Translate Linux termios to macOS.
FIONREAD (0x541B) — bytes available for reading.
FIONBIO (0x5421) — set non-blocking mode.

### 9b: ioctl passthrough framework
For ioctls we don't recognize, return -ENOTTY instead of the current
behavior. Add a dispatch table for known ioctls.

## Phase 10: Timer and event infrastructure

### 10a: timerfd (85, 86, 87)
timerfd_create, timerfd_settime, timerfd_gettime. Used by event-driven
daemons (nginx, systemd timers). Implement via kqueue EVFILT_TIMER or
pipe+thread.

### 10b: signalfd (74)
Convert signals to readable file descriptors. Used by event loops.

### 10c: inotify (26, 27, 28)
inotify_init1, inotify_add_watch, inotify_rm_watch. File system event
monitoring. Used by build tools (entr, watchman), editors, daemons.

### 10d: getitimer (102) / setitimer (103) full implementation
Current setitimer is a stub. Need real implementation via macOS setitimer
with signal translation.

## Phase 11: Extended file metadata

### 11a: xattr family (5-10)
setxattr, lsetxattr, fsetxattr, getxattr, lgetxattr, fgetxattr,
listxattr, llistxattr, flistxattr, removexattr. Used by tar for
preserving attributes, and by capability-aware programs.
Delegate to macOS xattr APIs.

### 11b: ACL / capability emulation
Virtual capability state (like virtual creds). capget/capset (90, 91).
Return full caps when euid==0 in virtual creds.

## Phase 12: Process and scheduling

### 12a: More prctl subcodes
PR_SET_DUMPABLE, PR_SET_NO_NEW_PRIVS, PR_SET_SECCOMP, PR_CAPBSET_READ,
PR_SET_SECUREBITS. Many are stubs (return 0) but some need real tracking.

### 12b: personality (135)
Execution domain. Usually just return 0 (PER_LINUX). Some programs check
this.

### 12c: sched_setscheduler / sched_getscheduler (119, 120)
Process scheduling policy. Stub as SCHED_OTHER.

### 12d: clock_nanosleep (115) / clock_getres (114)
Precise sleep and clock resolution queries. Translate clock IDs.

### 12e: nanosleep (101)
Simple sleep with nanosecond precision. Delegate to macOS nanosleep.

## Phase 13: /proc filesystem expansion

### 13a: /proc/self additions
- /proc/self/cgroup — return empty or "0::/" (cgroup2)
- /proc/self/limits — resource limits table
- /proc/self/io — I/O statistics (can be zeros)
- /proc/self/mountinfo — expand with rootfs mounts
- /proc/self/environ — guest environment

### 13b: System-wide /proc
- /proc/uptime — system uptime
- /proc/loadavg — load averages
- /proc/stat — CPU statistics
- /proc/version — kernel version string
- /proc/filesystems — supported fs types
- /proc/mounts — mounted filesystems

### 13c: /proc/net
- /proc/net/tcp, /proc/net/udp, /proc/net/unix — socket tables
- /proc/net/if_inet6 — IPv6 interface addresses

### 13d: /sys filesystem
Basic sysfs stubs for programs that probe /sys/devices, /sys/class.

## Phase 14: Thread correctness

### 14a: Per-thread signal masks
GUEST_SIGMASK should be per-thread (thread-local or per-pthread-key).
Currently global — breaks multi-threaded signal handling.

### 14b: Futex CMP_REQUEUE
Needed for pthread_cond_broadcast in glibc/musl. Currently missing.

### 14c: Robust futex list
set_robust_list is stubbed. Full implementation needed for mutex
cleanup on thread death.

### 14d: Thread-directed signals
tgkill should deliver to specific thread, not just process-wide kill.
Needs tid-to-pthread mapping.

## Phase 15: Namespace and container emulation

### 15a: Virtual mount table
Track a virtual mount table. mount/umount/pivot_root operate on it.
Path translation already exists (FAKELINUX_ROOT) — extend it.

### 15b: unshare / setns stubs
Return success for user namespace operations. We already emulate the
effect (virtual creds, virtual root).

### 15c: seccomp (stub)
Return success for SECCOMP_SET_MODE_FILTER. We don't need to actually
filter since we control all syscalls.

### 15d: Path traversal hardening
Sanitize ".." in rootfs paths to prevent escaping FAKELINUX_ROOT.
Currently documented as a known issue.

## Phase 16: Misc syscalls for full compatibility

These are less critical but show up in various programs:

- copy_file_range (285) — efficient file copy
- splice/tee/vmsplice (76, 77, 75) — zero-copy I/O
- memfd_create (279) — anonymous memory files
- mlock/munlock/mlockall (228, 229, 230) — memory locking (stub OK)
- msync (227) — memory sync
- mremap (216) — remap memory (hard — macOS doesn't have this)
- mincore (232) — page residency
- syslog (116) — kernel log (stub)
- reboot (142) — stub with exit
- sync/fsync/fdatasync (81, 82, 83) — file sync
- poll (ppoll already works, add poll wrapper)

## Priority order for implementation

1. **Phase 7a**: Signal mutex fix (prevents deadlocks NOW)
2. **Phase 8a-8d**: symlinkat, linkat, flock, utimensat (unblocks apk)
3. **Phase 8e-8f**: ftruncate, lstat (common file ops)
4. **Phase 9a**: Terminal ioctls (interactive programs)
5. **Phase 7b-7c**: SA_SIGINFO, SA_RESTART (musl correctness)
6. **Phase 10a-10c**: timerfd, signalfd, inotify (modern daemons)
7. **Phase 11-16**: Everything else, driven by what breaks
