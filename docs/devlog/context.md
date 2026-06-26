# fakelinux — Session Context & Development History

## What This Is

A Rust program that runs **unchanged aarch64 Linux ELF binaries** on macOS Apple Silicon. No CPU emulation — the CPU IS aarch64. We emulate the **Linux kernel ABI** (syscalls, TLS, /proc, signals, networking) on top of macOS.

**Current status (2026-04-12):**
- Python 3.12 (musl, Alpine): 100/100 reliability
- busybox (Alpine): sh, vi, echo, ls, cat, pipes, forks, command substitution
- Ubuntu glibc dynamic binaries: bash, ls, ps, id, cat, wget (busybox)
- **apt-get update**: downloads 4 InRelease files from Ubuntu repos, gpgv verification completes successfully (verified 2026-04-12)
- **HTTP networking**: fully working (DNS, TCP connect, HTTP fetch)
- 26/26 test suite passing
- Container mode with virtual PID namespace via shared memory

## Architecture Overview

### Instruction Interception: UDF/SIGILL (not BRK/SIGTRAP)

Early versions used BRK/SIGTRAP. **Switched to UDF/SIGILL** because macOS's SIGTRAP handler clobbers x18 in the mcontext.

Three instruction classes are patched to `UDF #0xF000`:
1. **SVC #0** (syscalls) → dispatched to syscall emulation
2. **MSR/MRS TPIDR_EL0** (TLS) → virtualized via per-thread pthread key
3. **x18-referencing instructions** → emulated with per-thread x18 storage (macOS reserves x18)

### Fork Trampoline

Fork can't happen inside a signal handler on macOS. The trampoline defers fork to outside signal context:
1. Signal handler marks fork pending, returns sentinel `0xFFFF_FFFF_0000_F0C0`
2. On sigreturn, `check_and_redirect()` redirects PC to executable trampoline page
3. Trampoline calls real `fork()`, sets x0 to result, restores guest regs

### Container Mode (`--container` / `--init`)

Shared-memory PID namespace (`src/pidns.rs`):
- `SharedPidTable` via `shm_open` + `mmap MAP_SHARED` (~1MB, 256K entries)
- Lock-free: `AtomicI32` array indexed by vpid, `fetch_add` for allocation
- Survives `execve` via env vars: `FAKELINUX_CONTAINER`, `FAKELINUX_VPID`, `FAKELINUX_VPPID`
- Init process (`--container`): creates shm, registers as vpid 1
- Child processes: attach to existing shm on startup via env var detection

### Virtual /proc Filesystem (`src/procfs.rs`)

Two mechanisms:
- **Regular files** (`/proc/self/stat`, `/proc/meminfo`, etc.): served via pipe fds (write content, close write-end, return read-end)
- **Directories** (`/proc`, `/proc/<pid>`, `/proc/self`): virtual fd tracking with synthetic `getdents64` entries

Virtual directory system:
- `alloc_virtual_fd()`: creates a pipe, closes write-end, returns read-end as marker fd
- `register_virtual_dir()`: pre-generates dirent64 entries
- `try_getdents64()`: intercepts getdents64 on virtual fds, returns synthetic entries
- `on_close()`: cleanup on fd close
- `try_stat()` / `try_statx()` / `try_fstat_virtual()`: stat interception for /proc paths

---

## Critical Translations (Linux ↔ macOS)

### sockaddr Translation (`src/net.rs`)

**Root cause of early networking failures.** Linux and macOS sockaddr layouts differ:
- Linux: `{ u16 sa_family; u8 sa_data[14]; }` — family as u16 at offset 0
- macOS: `{ u8 sa_len; u8 sa_family; u8 sa_data[14]; }` — len at offset 0, family at offset 1

Without translation, `AF_INET=2` stored as `[0x02, 0x00]` is read by macOS as `sin_len=2, sin_family=0` → `EAFNOSUPPORT`.

`linux_sockaddr_to_mac()` / `mac_sockaddr_to_linux()` fix in-place before/after every connect, bind, sendto, accept, recvfrom, getsockname, getpeername.

### Socket Option Translation (`src/translate.rs`)

Linux `SOL_SOCKET=1`, macOS `SOL_SOCKET=0xffff`. All SO_* names differ:
- `SO_ERROR`: Linux=4, macOS=0x1007
- `SO_REUSEADDR`: Linux=2, macOS=0x4
- `SO_SNDBUF/RCVBUF`: Linux=7/8, macOS=0x1001/0x1002
- etc.

`translate_sockopt()` maps level+optname. `getsockopt(SO_ERROR)` also translates the returned errno value.

### MSG Flag Translation (`src/net.rs`)

**Root cause of DNS failure.** Linux `MSG_NOSIGNAL=0x4000`, macOS `MSG_NOSIGNAL=0x80000`. On macOS, `0x4000` = `MSG_RCVMORE` — sending DNS queries with this flag silently corrupted them.

`translate_msg_flags()` handles: `MSG_NOSIGNAL` (0x4000→0x80000), `MSG_DONTWAIT` (0x40→0x80), strips `MSG_MORE` and `MSG_CMSG_CLOEXEC`.

### fcntl F_GETFL/F_SETFL Flag Translation (`src/translate.rs`)

**Root cause of apt-get http method hang.** File status flags differ:
- `O_NONBLOCK`: Linux=0x800 (0o4000), macOS=0x4
- `O_APPEND`: Linux=0x400 (0o2000), macOS=0x8
- `O_ASYNC`: Linux=0x2000, macOS=0x40

Without translation, `fcntl(F_SETFL, 0x800)` set a wrong macOS flag instead of O_NONBLOCK. glibc thought fd was non-blocking but macOS kernel left it blocking. Blocking `read()` returned 0 (EOF) instead of blocking properly.

`linux_fl_to_mac()` / `mac_fl_to_linux()` applied in `do_fcntl` for F_SETFL/F_GETFL.

### fcntl F_GETLK/F_SETLK/F_SETLKW (`src/translate.rs`)

Linux and macOS `struct flock` have different field order:
- Linux aarch64: `{ i16 l_type, i16 l_whence, [pad 4], i64 l_start, i64 l_len, i32 l_pid }`
- macOS: `{ i64 l_start, i64 l_len, i32 l_pid, i16 l_type, i16 l_whence }`

`linux_flock_to_mac()` / `mac_flock_to_linux()` translate before/after fcntl call.

### msghdr Translation (`src/net.rs`)

Linux aarch64 msghdr = 56 bytes, macOS = 48 bytes. Difference: `msg_iovlen` and `msg_controllen` are `size_t` (8 bytes) on Linux, `int`/`socklen_t` (4 bytes) on macOS.

`linux_msghdr_to_mac()` properly extracts fields. `do_sendmsg`/`do_recvmsg` translate before/after kernel call.

### Open Flag Translation (`src/translate.rs`)

`translate_open_flags()` maps all Linux→macOS open flags. Already existed before this session.

### Errno Translation (`src/translate.rs`)

`mac_errno_to_linux()` / `linux_errno()` — errnos 1-34 are mostly identical, diverge above 34. EAGAIN: macOS=35, Linux=11.

---

## Fixes Made This Session (2026-04-12)

### Syscall Stubs
- `sched_setscheduler` (119) → return 0
- `PR_CAPBSET_READ` (0x17=23) in prctl → return 1 (virtual root)
- `PR_CAPBSET_DROP` (0x18=24) → return 0

### procfs Enhancements
- `/proc/<pid>/...` path normalization (maps real PID or virtual PID to `/proc/self/...`)
- `/proc/uptime`, `/proc/stat` (with btime), `/proc/sys/kernel/pid_max`
- `try_stat()` for /proc paths in `do_newfstatat`
- `try_statx()` for /proc paths in `do_statx`
- Virtual directory fd system replacing temp directory approach
- `generate_for_other_pid()` for `/proc/<vpid>/stat|status|cmdline` of container processes
- Trailing slash handling in all procfs functions

### Container Mode
- `--container` flag (backward compat: `--init`)
- `src/pidns.rs`: shared memory PID table via shm_open
- Virtual PID translation in: getpid, getppid, kill, tgkill, wait4, setpgid, getpgid, setsid, getsid
- Fork trampoline: pre-allocates vpid before fork, sets FAKELINUX_VPID/VPPID env vars for child, restores parent env after fork
- procfs uses virtual PIDs in /proc/self/stat, /proc/self/status, /proc directory listing

### Networking
- **sockaddr translation** (sin_len byte swap) in all socket functions
- **Socket option translation** (SOL_SOCKET 1→0xffff, all SO_* names)
- **MSG flag translation** (MSG_NOSIGNAL 0x4000→0x80000, MSG_DONTWAIT 0x40→0x80)
- **sendmmsg** (syscall 269) implementation — iterates mmsghdr array
- **msghdr translation** for sendmsg/recvmsg (56→48 byte struct conversion)

### fcntl
- **F_GETFL/F_SETFL flag translation** (O_NONBLOCK, O_APPEND, O_ASYNC)
- **F_GETLK/F_SETLK/F_SETLKW** with struct flock translation
- **F_DUPFD_CLOEXEC** (Linux cmd 1030)

### Permission Stubs (Virtual Root)
- `fchownat`, `fchown`: silently succeed when virtual euid=0 and real op fails
- `fchmodat`: strips `AT_SYMLINK_NOFOLLOW` (0x100, unsupported on macOS), succeeds when virtual root
- `fchmod`: same virtual root stub

### x18/Instruction Fixes
- **Bitfield instruction matching**: changed `(instr >> 23) & 0x3F == 0b100110` to `(instr >> 24) & 0x1F == 0b10011` — the N-bit (bit 23) is 1 for 64-bit SBFM/UBFM/BFM, was causing misses
- **SBFIZ emulation**: fixed incorrect shift+sign-extend to correct `sign_extend(val, width) << lsb`
- **SIMD scalar false positive**: added top bytes `0x5E, 0x7E, 0x5F, 0x7F` to SIMD exclusion in `references_x18()` — these are Advanced SIMD scalar instructions where register 18 means D18/V18, not GPR x18

### Alpine DNS Fix
- Changed `alpine-rootfs/etc/resolv.conf` from Docker-internal `0.250.250.200` to `8.8.8.8`

---

## Current Known Issues

### 1. apt-get gpgv Method Pipe Hang (RESOLVED)

**Status**: VERIFIED WORKING as of 2026-04-12. Multiple consecutive runs of `apt-get update` complete successfully.

**Previous symptoms (now resolved)**: apt-get downloads 4 InRelease files successfully, then hangs when gpgv method processes them.

**Resolution**: Fixed via `fcntl` F_GETFL/F_SETFL flag translation (`O_NONBLOCK`, `O_APPEND`, etc.) in `src/translate.rs`. The http method and gpgv method both benefited from this fix.
- The F_SETFL fix resolved the http method's version of this bug but not gpgv's

**Key observation**: After the F_SETFL fix, the http method's `read(0)` returns -11 (EAGAIN) instead of 0 (EOF), and the method correctly retries via pselect. The gpgv method's `read(0)` returns actual 0 (EOF), meaning the pipe write-end is truly closed by the parent.

### 2. realpath/flAbsPath Failure
`apt-get` prints `flAbsPath on /var/lib/dpkg/status failed - realpath (2: No such file or directory)`. glibc's `realpath()` walks the path from "/" using `openat`+`getdents64`+`fstatat`. The rootfs path translation may not fully satisfy all of realpath's internal stat calls.

### 3. ps STIME Column Shows 1970
The `btime` in `/proc/stat` is correct (epoch seconds) but `ps` may not parse it correctly, showing "1970" in the STIME column.

---

## Testing Commands

```bash
# Build
cargo build

# Unit tests
cargo test

# Full test suite (needs pre-compiled test binaries)
bash tests/run_tests.sh

# Python reliability (should be 10/10)
for i in $(seq 1 10); do r=$(timeout 10 env FAKELINUX_ROOT=./python-rootfs ./target/debug/fakelinux ./python-rootfs/usr/local/bin/python3 -c 'print(42)' 2>/dev/null); [ "$r" = "42" ] && printf "." || printf "X"; done; echo

# Ubuntu bash
timeout 5 env FAKELINUX_ROOT=./ubuntu-rootfs ./target/debug/fakelinux ./ubuntu-rootfs/bin/bash -c 'echo hello' 2>&1

# ps in container mode
timeout 5 env FAKELINUX_ROOT=./ubuntu-rootfs ./target/debug/fakelinux --container ./ubuntu-rootfs/usr/bin/ps -ef 2>/dev/null

# HTTP fetch (busybox wget)
timeout 10 env FAKELINUX_ROOT=./alpine-rootfs ./target/debug/fakelinux ./alpine-rootfs/bin/busybox wget -q -O /dev/null http://example.com/ 2>&1

# apt-get update (downloads InRelease, hangs on gpgv)
timeout 60 env FAKELINUX_ROOT=./ubuntu-rootfs ./target/debug/fakelinux --container ./ubuntu-rootfs/usr/bin/apt-get update 2>&1 | grep -v "^fakelinux:"

# apt http method standalone (completes full HTTP fetch)
(printf '601 Configuration\nConfig-Item: Acquire::http::Timeout=10\n\n600 URI Acquire\nURI: http://example.com/\nFilename: /tmp/test\n\n'; sleep 30) | timeout 20 env FAKELINUX_ROOT=./ubuntu-rootfs ./target/debug/fakelinux ./ubuntu-rootfs/usr/lib/apt/methods/http 2>/dev/null

# ALWAYS use timeout when running fakelinux
```

## Source File Summary

| File | Purpose |
|------|---------|
| `main.rs` | CLI entry, `--container` flag, env var detection, subsystem init |
| `trap.rs` | SIGILL handler, x18/TPIDR emulation, instruction decoder, crash handler |
| `loader.rs` | ELF loading, SVC/TPIDR/x18 patching, relocations, stack setup |
| `syscall.rs` | 100+ Linux syscall emulations |
| `translate.rs` | Linux↔macOS translation: flags, errno, stat, fcntl, flock, sockopt |
| `net.rs` | Socket syscalls, sockaddr/msghdr/MSG translation, sendmmsg |
| `thread.rs` | Fork/clone trampolines, futex, wait4, thread creation |
| `trampoline.rs` | Generic trampoline infrastructure (fork, mprotect+patch) |
| `signal.rs` | Guest signal delivery, rt_sigreturn, sigaction table |
| `procfs.rs` | Virtual /proc filesystem, virtual fd tracking, synthetic getdents64 |
| `pidns.rs` | Shared-memory PID namespace for container mode |
| `rootfs.rs` | Path translation (FAKELINUX_ROOT / FAKELINUX_SYSROOT) |
| `elf.rs` | ELF parser |
| `epoll.rs` | epoll emulation |
| `eventfd.rs` | eventfd emulation |
| `creds.rs` | Virtual credential (uid/gid) management |
| `linux.rs` | Linux ABI constants (syscall numbers, etc.) |
| `bin/fakelinux-pull.rs` | OCI image puller (Docker Hub, ghcr.io) |

## Active Bug: apt-get gpgv pipe hang (detailed debugging notes)

### Symptoms
apt-get downloads 4 InRelease files successfully, then hangs. The gpgv
method child gets `read(0) = 0` (EOF on stdin) even though the parent
should keep the pipe's write end open.

### What was investigated and ruled out

1. **Signal handler theory**: Tested pselect inside SIGILL handler on
   native macOS — works correctly even with 100+ handler invocations,
   file I/O between calls, and sigreturn-based PC advancement. Ruled out.

2. **procfs virtual fd interference**: Confirmed no virtual fd shadows
   fd 0. `alloc_virtual_fd()` creates pipe fds that are always >= 3.

3. **close(0) called by guest**: Added logging to `do_close` — fd 0 is
   NEVER closed via our syscall handler. No `close_range` or `dup3`
   targets fd 0 either.

4. **Rootfs path translation**: Same EOF happens WITHOUT `FAKELINUX_ROOT`
   (using only `FAKELINUX_SYSROOT`). Not a rootfs issue.

5. **glibc vs musl**: Cross-compiled musl-static test binary shows
   correct pselect behavior (returns 0/timeout when pipe is open). Ubuntu
   glibc `cat` also works correctly (blocks on read). Issue is specific
   to apt method binaries.

6. **Non-blocking probe**: Added O_NONBLOCK probe before the failing
   `read(0)`: returns `-1 errno=35 (EAGAIN)` confirming pipe IS open and
   has no data. Then immediately after restoring blocking mode, `read(0)`
   returns 0 (EOF). This led to discovering the fcntl bug.

### The fcntl F_GETFL/F_SETFL bug (FIXED for http method)

**Root cause found**: `do_fcntl` passed Linux flag values directly to
macOS for `F_SETFL`, and returned macOS flag values to the guest for
`F_GETFL`. Linux `O_NONBLOCK=0x800`, macOS `O_NONBLOCK=0x4`.

When glibc's apt http method called `fcntl(0, F_SETFL, O_NONBLOCK)`, we
passed `0x800` to macOS which interpreted it as `O_SHLOCK` (silently
ignored). The fd stayed blocking. Then when the method read from it,
instead of getting `-EAGAIN` (which the method would handle by retrying
via pselect), it got `0` (EOF) from some other cause.

**Fix**: Added `linux_fl_to_mac()` and `mac_fl_to_linux()` translation
functions for O_NONBLOCK, O_APPEND, O_ASYNC. Applied in `do_fcntl` for
F_SETFL (translate arg) and F_GETFL (translate result).

After fix: http method gets `-EAGAIN` correctly, retries via pselect,
and successfully downloads files. But gpgv method still gets EOF.

### Remaining gpgv issue

The gpgv method may NOT use `fcntl(F_SETFL, O_NONBLOCK)` — it might use
a different I/O pattern. Its `read(0)` returns 0 (genuine EOF) meaning
the parent's write-end of the pipe is truly closed.

**Key observation**: Parent's pselect after HTTP phase shows
`nfds=7, rd:0x60` (watching fds 5 and 6) returning 0 (timeout). Children
write to their stdout (fd 1) successfully, but the parent never sees the
data on fds 5/6. This suggests a pipe fd mismatch — the child's stdout
pipe connects to a DIFFERENT parent fd than what the parent watches.

**Theory**: The parent creates pipes for child A, then for child B. The
pipe fd numbers get reused after closes. By the time the parent enters
its polling loop, the fd numbers it watches may no longer correspond to
the correct pipe endpoints. This is exacerbated by fakelinux's re-exec
pattern (each execve replaces the process image).

### What to investigate next

1. **Trace the exact pipe2/dup3/fork/close sequence** for the gpgv child
   creation, mapping which fd numbers the parent keeps vs closes.

2. **Check if `do_execve`'s use of host `environ`** (line 1254 in
   syscall.rs) drops guest environment variables that apt uses to
   communicate pipe fd numbers to children.

3. **Test with `FAKELINUX_TRACE=1`** and grep for `syscall 59` (pipe2)
   and `syscall 24` (dup3) around the gpgv fork to see the fd allocation.

4. **Consider adding fd-to-pid tracking** to understand which process
   holds which pipe ends at any given time.

## Session Commits (2026-04-12)

```
1f958e5 Fix x18 patching corrupting .dynstr (program header fallback)
3951347 Add missing syscall stubs + procfs for ps support
4cdead9 Add --container mode with virtual PID namespace
8a94b6c Rewrite PID namespace with shared memory (cross-execve)
3e5f939 Fix setpgid/getsid PID translation + /proc/stat
8f34cf8 Fix TIOCSPGRP/TIOCGPGRP PID translation (terminal fix)
d4e41de Improve /proc: enumerate all PIDs, fix stat field count
f584bdd Rewrite procfs with virtual fd + synthetic getdents64
48615b0 Add close_range, faccessat2, fix RLIMIT_NOFILE
9a8aafc Fix networking: sockaddr sin_len, fcntl F_SETLK, fchown stubs
ca19261 Add sendmmsg, socket option level/name translation
df7afa6 Add MSG_NOSIGNAL/MSG_DONTWAIT flag translation
3243c26 Fix pselect6 sigmask extraction from Linux wrapper struct
39772c9 Fix fcntl F_GETFL/F_SETFL flag translation (O_NONBLOCK)
e25d2df Fix x18 SIMD false positives + SBFM bitfield check
```
