# Fakelinux Development Diary

## Overview

Fakelinux is a Rust-based aarch64 (ARM 64-bit) Linux emulator that runs on macOS. It allows running Linux ELF binaries natively on macOS by emulating Linux syscalls.

## Quick Start

### Prerequisites
- macOS (ARM/M-series chip)
- Rust toolchain: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- Build: `cargo build`

### Building the Binary

```bash
cargo build
# or for release:
cargo build --release
```

### Getting the Ubuntu Root Filesystem

Fakelinux includes a built-in tool `fakelinux-pull` to pull OCI/Docker images without Docker:

```bash
# Build fakelinux-pull if not already built
cargo build -p fakelinux-pull

# Pull Ubuntu 24.04 ARM64 rootfs
./target/debug/fakelinux-pull ubuntu:24.04 ubuntu-rootfs
```

This will:
1. Authenticate with Docker Hub
2. Fetch the manifest and select the linux/arm64 variant
3. Download and extract the rootfs layer
4. Strip macOS quarantine xattrs

### Initialize Required Directories

After pulling the rootfs, you need to create some required directories:

```bash
mkdir -p ubuntu-rootfs/var/lib/dpkg ubuntu-rootfs/var/cache/apt ubuntu-rootfs/var/lib/apt/lists
touch ubuntu-rootfs/var/lib/dpkg/status
echo "nameserver 8.8.8.8" > ubuntu-rootfs/etc/resolv.conf
```

### Running Commands in the Root Filesystem

```bash
# Set FAKELINUX_ROOT to point to your rootfs directory (relative paths work)
FAKELINUX_ROOT=./ubuntu-rootfs ./target/debug/fakelinux --container <binary> [args...]

# Example: run apt-get update
FAKELINUX_ROOT=./ubuntu-rootfs ./target/debug/fakelinux --container ./ubuntu-rootfs/usr/bin/apt-get update
```

The `--container` flag runs the process in virtual PID namespace mode (as PID 1).

### Common Issues

#### "cannot read '/usr/bin/apt-get': No such file or directory"

The binary path must be a macOS filesystem path. Use the full relative path:
```bash
# WRONG:
./target/debug/fakelinux --container /usr/bin/apt-get update

# CORRECT:
./target/debug/fakelinux --container ./ubuntu-rootfs/usr/bin/apt-get update
```

#### Symlinks with Absolute Targets Break Out of Rootfs

`cat /etc/alternatives/which` fails with "No such file or directory" even though
`ls /etc/alternatives/which` works. The symlink target is an absolute path like
`/usr/bin/which.debianutils`. macOS resolves symlinks on the HOST filesystem, not
in the rootfs. Our rootfs translation intercepts syscall path arguments but not
kernel-level symlink resolution.

Also related: `realpath` fails on rootfs paths (`flAbsPath on /var/lib/dpkg/status failed`)
because glibc's realpath walks the path from "/" using openat+readlinkat+fstatat, and
symlink targets escape the rootfs.

### setpgid Returns ESRCH in Interactive Bash

`bash: child setpgid (1 to 1): No such process` — bash tries to set the child's
process group but gets ESRCH. Our setpgid implementation may not handle the PID
translation correctly in container mode.

### DNS Resolution Fails

Create `/etc/resolv.conf` in the rootfs:
```bash
echo "nameserver 8.8.8.8" > ubuntu-rootfs/etc/resolv.conf
```

#### apt-get Hangs

If `apt-get update` hangs after downloading package lists, check if there are zombie `gpgv` or `http` method processes:
```bash
ps aux | grep fakelinux
pkill -f "fakelinux.*gpgv"
pkill -f "fakelinux.*http"
```

## Architecture

### Key Components

- **loader.rs**: ELF binary loading and dynamic linking
- **syscall/**: Linux syscall emulation
- **translate.rs**: Linux-to-macOS flag/constant translation
- **rootfs.rs**: Path translation layer for chroot-like isolation
- **trap.rs**: Signal handling and syscall interception
- **thread.rs**: Thread management and TLS

### Environment Variables

- `FAKELINUX_ROOT`: Full rootfs path (all absolute paths translated)
- `FAKELINUX_SYSROOT`: Library-only path (only library/linker paths translated)
- `FAKELINUX_TRACE`: Enable syscall tracing
- `FAKELINUX_CONTAINER`: Set virtual PID namespace mode
- `FAKELINUX_VPID`: Override virtual PID
- `FAKELINUX_NO_X18`: Disable x18 patching

### Syscall Translation

The `translate.rs` module handles conversion between Linux and macOS:
- File flags: `O_NONBLOCK`, `O_APPEND`, `O_CLOEXEC`, etc.
- Socket options
- mmap flags and protections

## Troubleshooting

### Debugging Syscalls

Enable trace mode to see all syscalls:
```bash
FAKELINUX_ROOT=./ubuntu-rootfs FAKELINUX_TRACE=1 ./target/debug/fakelinux --container ./ubuntu-rootfs/usr/bin/apt-get update
```

### Common Syscall Numbers

- 57: clone (create thread/process)
- 63: read
- 64: write
- 72: pselect6
- 80: fcntl
- 94: brk
- 214: mmap
- 260: wait4

### SIGILL or Unhandled Instructions

If you see `SIGILL at pc=... instr=...`, check:
1. Are TLS register accesses (MSR/MRS tpidr_el0) properly patched?
2. Are x18 instructions handled?
3. Is the code region properly identified as code vs data?

## Recent Fixes

### fcntl F_GETFL/F_SETFL Flag Translation (2024-04-12)

Fixed translation of file status flags between Linux and macOS:
- Linux `O_NONBLOCK` (0x800) → macOS `O_NONBLOCK` (0x80)
- Linux `O_APPEND` (0x400) → macOS `FAPPEND` (0x8)
- Linux `O_CLOEXEC` (0x80000) → macOS `FCLOSEXEC` (0x2000000)
- Added `translate_fcntl_getfl_status()` for F_GETFL response translation

### pselect6 Sigset Extraction (2024-04-12)

Fixed sigmask extraction from pselect6's 6th argument. The sigmask pointer
and size were being mishandled, causing incorrect signal masks.

## Known Issues

### apt-get update Hangs After Downloading Release Files (Active Investigation 2026-04-13)

**Status**: Downloads complete, hangs during gpgv verification. Multiple bugs found and fixed;
one remaining issue in fork child code path routing.

**Symptoms**:
1. Resolves DNS and connects to Ubuntu mirrors ✓
2. Downloads 4 InRelease files (noble, noble-updates, noble-backports, noble-security) ✓
3. Spawns gpgv for signature verification ✓
4. **HANGS** after "Get:1-4" messages appear
5. First http and first gpgv method children die with signal 2 (SIGINT), get respawned

**Investigation findings (2026-04-13)**:

#### Signal 2 (SIGINT) deaths of first method children

The parent apt-get deliberately sends `kill(child, SIGINT)` after reading each method's
"100 Capabilities" response. This appears to be normal apt behavior — apt probes workers
and restarts them. The first child has SIGINT=SIG_DFL (the parent sets all signals to SIG_DFL
before fork), so the child dies. The second instance installs a custom SIGINT handler fast enough
to survive.

**Debugging technique**: Added PID annotations to read/write/close/kill trace messages to
distinguish parent (apt-get) vs child (method) syscalls. Without PIDs, the interleaved output
is unreadable. Pattern: `fakelinux: [PID] read(fd, count=N) = R`.

#### Root cause of hang: pipe fd aliasing after close

After all 4 downloads complete, someone closes fds 5 and 6 (the parent's pipe read-ends
for http and gpgv methods). Then:

1. `/dev/null` gets opened → assigned fd 5 (reusing the freed number)
2. `dup3(5, 1)` and `dup3(5, 2)` redirect stdout/stderr to /dev/null
3. Parent enters pselect6 loop watching fds 5 and 6 (rd:0x60) with 500ms timeout
4. pselect returns 0 every time — fd 5 is /dev/null (not a pipe), fd 6 is gone
5. gpgv method tries `write(1, 189)` → gets **EPIPE** (-32) because pipe read-end is closed
6. gpgv method sees EOF on stdin → exits
7. Parent never sees exit because it's watching wrong fds → infinite loop

**Key evidence**:
- `[parent] close(6)` then `close(5)` right before hang loop
- `openat("/dev/null") → fd 5` immediately after
- `[gpgv_method] write(1, count=189) = -1 (EPIPE)` — pipe broken
- `pselect6 nfds=7 rd:0x60→0x0 ret=0 tv=0s+500000000ns` — watching wrong fds

**Root causes found and fixed (2026-04-13)**:

1. **execve ENOENT bug (FIXED)**: `do_execve` fell back to the current binary for ALL
   non-ELF files, including files that don't exist. This broke glibc's `execvp` PATH
   search: the first non-existent PATH entry (e.g., `/usr/local/sbin/gpgv`) would succeed
   with the WRONG binary (the current process's binary), preventing execvp from finding
   the correct binary at `/usr/bin/gpgv`. Fix: return -ENOENT for missing files, only
   use fallback when file exists but isn't ELF (Mach-O binary on macOS).

   This also caused the user-reported bug where `vi` in interactive bash gave a nested
   bash session instead of "command not found".

2. **Pipe fd aliasing (was caused by #1)**: Before the fix, the gpgv method re-exec'd
   ITSELF instead of the gpgv tool. The extra process layer caused pipe endpoints to
   mismatch between parent and child, leading to EPIPE and infinite pselect loop.

**Remaining issue: fork child runs parent code path**

After fixing #1, the gpgv method now correctly has no nested processes. But the method's
fork child (which should exec the real gpgv tool) instead runs the METHOD's processing
code (reading InRelease, writing parsed data). The child never calls execve.

Investigation confirmed:
- Fork trampoline correctly sets x0=0 for child (verified with trace)
- glibc's fork wrapper instructions at resume_pc are intact (not corrupted by patcher):
  `CMN x0, #1, LSL #12; B.HI; MOV w2, w0; CBNZ w0, parent_label`
- The CBNZ w0 should NOT branch for w0=0, routing to child path
- Yet the child executes parent code (write config, read InRelease, process data)

**Theories for remaining issue**:
- A register (x5, used for thread pointer math in glibc's fork child path) might be
  incorrectly saved/restored through the fork trampoline
- The set_robust_list SVC in glibc's child path might somehow affect the return path
- The MOV w0, w2 after set_robust_list should restore fork return=0, but w2 might
  have been corrupted

**What to investigate next**:
- Add per-syscall tracing in the child process immediately after fork
- Verify x0 and x2 values through each instruction of glibc's fork child path
- Check if the set_robust_list handler corrupts any registers

**Debugging techniques used**:
- `FAKELINUX_TRACE=1` with filtered grep for specific syscalls
- Added PID to trace: `let pid = unsafe { libc::getpid() }` in do_read/do_write/do_close
- Saved full trace to `/tmp/apt_trace.log` and used line-number searches
- `ps aux | grep fakelinux` during hang to see live child processes
- `pselect6` timeout value logging to distinguish spin (0ns) from poll (500ms)
- `lsof -p PID | grep PIPE` during hang to verify pipe connectivity
- Pipe inode tracking (fstat st_ino) through fork/exec to detect pipe mismatch
- Fork trampoline x0 logging to verify child gets correct return value
- Instruction dump at fork resume PC to verify glibc code isn't corrupted
- Binary analysis of glibc's `__libc_fork` to understand the fork check pattern

#### Signal fixes (2026-04-13)

Three signal-related bugs were fixed (may not be root cause of hang but improve correctness):

1. **PENDING_SIGNALS not cleared after fork** (signal.rs, trap.rs): Child inherited parent's
   pending signals via COW. POSIX requires child's pending set to be empty.

2. **SIG_IGN not preserved across execve** (syscall.rs, main.rs): When do_execve() re-execs
   fakelinux, the new process had fresh statics with all GUEST_SIGACTIONS = SIG_DFL. Now
   encodes SIG_IGN bitmask in `FAKELINUX_SIGIGN` env var, read on startup.

3. **Signal mask not inherited across execve** (main.rs): GUEST_SIGMASK reset to 0 on re-exec.
   Now propagated via `FAKELINUX_SIGMASK` env var.

**Workaround**: Use `timeout` to force termination:
```bash
FAKELINUX_ROOT=./ubuntu-rootfs timeout 120 ./target/debug/fakelinux --container ./ubuntu-rootfs/usr/bin/apt-get update
```

### DNS Resolution Fails

Create `/etc/resolv.conf` in the rootfs: