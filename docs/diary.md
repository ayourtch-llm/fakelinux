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

#### DNS Resolution Fails

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

### apt-get update Hangs After Downloading Release Files

After DNS and fcntl fixes, `apt-get update` successfully:
1. Resolves DNS and connects to Ubuntu mirrors ✓
2. Downloads Release files (InRelease, updates, backports, security) ✓
3. Spawns gpgv for signature verification ✓
4. **HANGS** after "Get:1-4" messages appear (no SIGPIPE visible)

The processes seem to complete but apt-get never exits. This suggests a subprocess communication issue - the http/gpgv methods communicate with apt via pipes and something in that protocol isn't working correctly.

**Workaround**: Use `timeout` to force termination after apt has fetched what it needs:
```bash
FAKELINUX_ROOT=./ubuntu-rootfs timeout 120 ./target/debug/fakelinux --container ./ubuntu-rootfs/usr/bin/apt-get update
```

Or run in background and kill after ~60 seconds when "Get:X" messages appear.

**Investigation notes**:
- No SIGPIPE visible in trace
- gpgv and http method processes do run and get patched
- apt forks them and waits via wait4
- The hang is in the parent apt-get waiting for something that never comes

### DNS Resolution Fails

Create `/etc/resolv.conf` in the rootfs: