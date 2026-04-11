# fakelinux — User-Mode Linux Emulator for aarch64 on macOS Apple Silicon

## What This Is

A Rust program (~3000 lines) that runs **unchanged aarch64 Linux ELF binaries** on macOS Apple Silicon (M1/M2/M3). No CPU emulation needed — the CPU IS aarch64. We emulate the **Linux kernel ABI** (syscalls, TLS, /proc filesystem) on top of macOS.

Successfully runs: Alpine musl static-PIE binaries, Ubuntu glibc static-PIE, **busybox** (echo, uname, id, ls, cat, pwd, wc, head, whoami, uptime), and **interactive busybox sh** with fork+exec+pipes.

## Architecture

### Syscall Interception: SVC→BRK + SIGTRAP Signal Handler

Linux aarch64 syscalls use `SVC #0` (encoding `0xD4000001`). We:

1. **Load** the ELF binary into memory (parse ELF64, mmap PT_LOAD segments)
2. **Patch** every `SVC #0` instruction to `BRK #0xF000` (encoding `0xD43E0000`)
3. **Install** a `SIGTRAP` signal handler on a dedicated sigaltstack
4. When the guest hits a BRK, our handler reads `x8` (syscall number), `x0-x5` (args), emulates the syscall, writes the result to `x0`, advances PC by 4, and returns

### TPIDR_EL0 Virtualization

macOS Apple Silicon clobbers `TPIDR_EL0` on every signal entry/return (restoring it to ~0x1004). Linux binaries use TPIDR_EL0 for Thread-Local Storage (TLS).

**Solution**: Intercept all `MSR/MRS tpidr_el0` instructions by patching them to `BRK #0xF000` and storing the original instruction in a **side table** (frozen sorted Vec for lock-free binary search). The signal handler looks up the original instruction, reads/writes an `AtomicU64` global (`GUEST_TPIDR`) instead of the hardware register.

Key detail: `GUEST_TPIDR` must be initialized to the macOS TPIDR_EL0 value (~0x1004) at startup, otherwise guest code that reads TPIDR before `__set_thread_area` gets 0 and hangs.

### Fork: Return-Into-Trampoline

Fork from inside a signal handler is broken on macOS — `sigreturn` re-blocks SIGTRAP in the child (the kernel restores the signal mask from internal state, ignoring `uc_sigmask`).

**Solution**: Don't fork in the signal handler. Instead:

1. When `clone(fork)` is detected, save guest registers to `FORK_REGS`
2. Set the mcontext's PC to a **fork trampoline** (mmap'd executable page)
3. Signal handler returns → sigreturn takes us to the trampoline (OUTSIDE signal context!)
4. Trampoline calls `fork()` normally — no signal mask issues
5. Both parent and child restore callee-saved registers and jump to the saved guest PC
6. Child gets `x0=0`, parent gets `x0=pid`

### Execve: Re-exec fakelinux

When the guest calls `execve`, we re-exec our own `fakelinux` binary with the guest binary path as the first argument. Key details:

- Resolve `/proc/self/exe` to the actual guest binary path
- If the target is a Mach-O (not ELF), fall back to the parent's guest binary (busybox sh finds `/usr/bin/uname` on macOS)
- Use host `environ` (not guest's) so env vars like `FAKELINUX_TRACE` propagate
- The re-exec'd fakelinux must also unblock SIGTRAP (inherited blocked from the parent's signal handler via `execve`)

### ELF Relocations

PIE (ET_DYN) binaries need `R_AARCH64_RELATIVE` relocations applied at load time. We parse the `PT_DYNAMIC` segment, find `DT_RELA`/`DT_RELASZ`, and apply: `*(base + r_offset) = base + r_addend`. The binary's own self-relocation code also runs (idempotent).

## Key macOS Apple Silicon Discoveries

### 1. PAGEZERO is 4GB and immovable
Non-PIE Linux binaries at `0x400000` can't be mapped. Reducing PAGEZERO via `-pagezero_size` produces "Malformed Mach-o" binaries. PIE binaries load above 4GB (we use `0x500000000`).

### 2. TPIDR_EL0 (~0x1004)
macOS barely uses it but **clobbers it on every signal entry AND return**. Also clobbered by the Darwin runtime during `BLR` calls into host code (discovered with help from GPT-5.4). Must be fully virtualized.

### 3. 16KB Pages
macOS uses 16KB pages. Linux guests expect 4KB. Issues:
- **Guard pages**: 4KB `PROT_NONE` mmap with `MAP_FIXED` would make entire 16KB page inaccessible. Skip sub-page guard pages.
- **mprotect**: Only protect fully-covered 16KB pages (round address UP, end DOWN) to avoid making adjacent writable data read-only.
- **brk**: Extends in 16KB increments.

### 4. Signal Mask After Fork+Exec
`execve` preserves the signal mask. If `fork()` was called from a signal handler, SIGTRAP is blocked. The re-exec'd process must install the handler BEFORE unblocking (otherwise pending SIGTRAP fires with `SIG_DFL=terminate`).

### 5. sigreturn Restores Signal Mask from Internal State
Setting `uc_sigmask = 0` in the ucontext has NO effect on macOS — the kernel restores the mask from its own saved state. This is why the return-into-trampoline approach is necessary for fork.

## Source Files

| File | Lines | Purpose |
|------|-------|---------|
| `main.rs` | 60 | CLI entry, subsystem init, jump to guest |
| `elf.rs` | 116 | ELF64 parser (zero deps) |
| `loader.rs` | 624 | mmap segments, SVC/TPIDR patching, relocations, stack setup, fork trampoline |
| `trap.rs` | 250 | SIGTRAP handler, TPIDR lookup, crash handler |
| `syscall.rs` | 600 | ~60 Linux syscall emulations |
| `translate.rs` | 263 | Linux↔macOS flag/errno/stat translation |
| `procfs.rs` | 213 | Virtual /proc filesystem |
| `thread.rs` | 370 | Fork trampoline, clone, futex, wait4 |
| `signal.rs` | 194 | Signal number translation |
| `linux.rs` | 104 | Linux ABI constants |

## Syscalls Implemented (~60)

**File I/O**: read, write, writev, openat, close, lseek, fstat, newfstatat, readlinkat, faccessat, getdents64, dup, dup3, pipe2, ioctl(TIOCGWINSZ)

**Memory**: brk, mmap, munmap, mprotect, madvise

**Process**: exit, exit_group, clone(fork+thread), execve, wait4, getpid, getppid, gettid, set_tid_address, set_robust_list, tgkill, sched_yield

**Filesystem**: getcwd, chdir, fchdir, mkdirat, unlinkat, renameat, fchmod, fchmodat, fchown, fchownat, umask

**Info**: uname, getuid/geteuid/getgid/getegid, getgroups, clock_gettime, getrandom, prlimit64

**Signals**: rt_sigaction, rt_sigprocmask (stubs with guest handler tracking)

**Other**: fcntl, futex(WAIT/WAKE), rseq(→ENOSYS), clone3(→ENOSYS)

## Flag/Errno Translation

Linux and macOS differ in:
- **Open flags**: `O_CREAT`(64→512), `O_APPEND`(1024→8), `O_NONBLOCK`(2048→4), `O_DIRECTORY`(65536→1048576), etc.
- **Errno**: `EAGAIN`(11→35), `ENOSYS`(38→78), `ELOOP`(40→62), `ENOTEMPTY`(39→66), network errnos 88-115
- **struct stat**: Field-by-field translation (different layouts, `st_mode` is u16 on macOS, u32 on Linux)
- **AT_FDCWD**: Linux=-100, macOS=libc::AT_FDCWD

## Branches

- **main**: Signal-based approach (working, production-ready)
- **bl-rewriting**: BL trampoline architecture (no signals on hot path, fork works natively, but TPIDR virtualization trampolines have a bug causing hangs — needs lldb debugging)

## Building & Testing

```bash
cargo build
# Generate test ELF (no cross-compiler needed)
cargo run --bin gen_test_elf > hello && chmod +x hello

# Get busybox from Alpine Docker
docker run --rm --platform linux/arm64 -v $PWD:/out alpine:latest \
  sh -c 'cp /bin/busybox.static /out/busybox'

# Run!
./target/debug/fakelinux ./busybox sh -c 'uname -a; ls / | head -5'
# → Linux fakelinux 6.1.0-fakelinux #1 SMP aarch64 Linux
# → Applications, Library, System, Users, Volumes

# Interactive shell
./target/debug/fakelinux ./busybox sh

# Syscall tracing
FAKELINUX_TRACE=1 ./target/debug/fakelinux ./busybox echo hello

# Build Alpine static-PIE test
docker run --rm --platform linux/arm64 -v $PWD:/out alpine:latest \
  sh -c 'apk add gcc musl-dev && echo "#include <stdio.h>
int main(){printf(\"Hello!\\n\");return 0;}" > /tmp/t.c && \
gcc -static-pie -o /out/hello_alpine /tmp/t.c'
./target/debug/fakelinux ./hello_alpine
```

## Known Limitations

1. **No dynamic linking** — only static/static-PIE binaries (PT_INTERP loading is scaffolded but untested)
2. **No thread creation** — clone with CLONE_THREAD is scaffolded but incomplete
3. **16KB page mismatch** — some edge cases with mmap/mprotect alignment
4. **Fork child startup slow** — each fork+exec re-loads fakelinux from scratch (~100ms)
5. **Missing syscalls** — socket, epoll, signalfd, etc. would need implementation for more complex programs

## Future Directions

1. **Dynamic linking**: Load `ld-linux-aarch64.so.1` from a sysroot, handle `PT_INTERP`
2. **Container support**: Add chroot emulation, path translation for rootfs
3. **BL rewriting** (branch): Fix TPIDR trampoline hang, eliminate signals from hot path entirely
4. **Thread support**: Implement CLONE_THREAD via pthreads
5. **Performance**: The signal-based approach has overhead (~1μs per syscall). BL rewriting would be faster.
