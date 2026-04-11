# fakelinux: Docker Replacement for macOS Apple Silicon

## Vision

Replace Docker Desktop on macOS with fakelinux — run Linux containers natively
on Apple Silicon without a VM. Since the CPU IS aarch64, we only need to emulate
the Linux kernel ABI (syscalls, /proc, signals), not the CPU itself. This means
near-native performance.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│  macOS Apple Silicon (aarch64-apple-darwin)           │
│                                                      │
│  ┌──────────────────────────────────────────────┐    │
│  │  fakelinux (Rust binary)                     │    │
│  │  ┌────────────┐  ┌───────────┐               │    │
│  │  │ ELF Loader │  │ Syscall   │               │    │
│  │  │ SVC→BRK    │  │ Emulation │               │    │
│  │  │ TPIDR virt │  │ ~100 calls│               │    │
│  │  └────────────┘  └───────────┘               │    │
│  │  ┌────────────┐  ┌───────────┐               │    │
│  │  │ /proc/     │  │ Container │               │    │
│  │  │ Virtual FS │  │ Runtime   │               │    │
│  │  └────────────┘  └───────────┘               │    │
│  └──────────────────────────────────────────────┘    │
│                                                      │
│  ┌──────────────────────────────────────────────┐    │
│  │  Container rootfs (extracted OCI image)       │    │
│  │  /usr/local/bin/python3                       │    │
│  │  /usr/bin/nginx                               │    │
│  │  etc.                                         │    │
│  └──────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────┘
```

## Phases

### Phase 7: Real-World Binary Support (current)
**Goal:** Run Python, Node.js, nginx from Alpine/Debian container images.

**What's needed:**
- [ ] getrandom syscall (Python needs it for hashseed)
- [ ] madvise (commonly called, can stub most advice values)
- [ ] prlimit64 (resource limits query)
- [ ] clone3 → ENOSYS stub (glibc/musl fall back to clone)
- [ ] rseq → ENOSYS stub (restartable sequences, optional)
- [ ] /proc/self/exe symlink (many programs read this)
- [ ] /proc/self/fd/ directory (Python, Node use this)
- [ ] Robust mmap with MAP_FIXED for large binaries
- [ ] Handle PAGEZERO (4GB) conflict for non-PIE binaries

**Success criteria:** `python3 -c 'print("hello")'` works from container image.

### Phase 8: OCI Image Support
**Goal:** `fakelinux run python:3.12-alpine -- python3 -c 'print("hello")'`

**What's needed:**
- [ ] OCI image puller (use `skopeo` or implement minimal registry client)
- [ ] Layer extraction and overlay (can use simple copy-on-write or overlayfs-lite)
- [ ] Image config parsing (entrypoint, cmd, env, workdir)
- [ ] `fakelinux pull <image>` command
- [ ] `fakelinux run <image> -- <command>` command
- [ ] Image cache in ~/.fakelinux/images/

**Success criteria:** Pull and run Alpine, Python, Node images by name.

### Phase 9: Networking & Services
**Goal:** Run network services (nginx, Redis, PostgreSQL) with port mapping.

**What's needed:**
- [ ] Port forwarding: `-p 8080:80` maps host port to guest
- [ ] SO_REUSEADDR/SO_REUSEPORT translation
- [ ] epoll_pwait / epoll_pwait2 (nginx uses these)
- [ ] sendmsg/recvmsg with cmsg (SCM_RIGHTS for fd passing)
- [ ] Unix socket improvements (abstract sockets)
- [ ] /proc/net/tcp, /proc/net/unix for service discovery

**Success criteria:** `fakelinux run -p 8080:80 nginx:alpine` serves HTTP.

### Phase 10: Docker-Compatible CLI
**Goal:** Drop-in replacement for `docker` command.

**What's needed:**
- [ ] `fakelinux` CLI with docker-compatible subcommands
- [ ] `fakelinux build` (invoke BuildKit or simple Dockerfile parser)
- [ ] `fakelinux compose` (parse docker-compose.yml, orchestrate containers)
- [ ] Container lifecycle (start, stop, restart, logs, exec)
- [ ] Volume mounts (-v /host/path:/container/path)
- [ ] Environment variables (-e KEY=VALUE)
- [ ] Container naming and listing
- [ ] Background/daemon mode (-d)

**Success criteria:** Existing docker-compose.yml files work with minimal changes.

### Phase 11: Namespace Virtualization
**Goal:** Support programs that expect Linux namespaces.

**What's needed:**
- [ ] Virtual PID namespace (translate PIDs, fake /proc/<pid>/)
- [ ] Virtual network namespace (per-container network stack)
- [ ] Mount namespace (per-container mount table)
- [ ] User namespace (UID/GID mapping)
- [ ] unshare/setns syscalls (virtual implementation)
- [ ] pivot_root/chroot

**Success criteria:** Container runtimes (runc/crun) can start under fakelinux.

### Phase 12: Performance (BL Rewriting)
**Goal:** Remove signal handlers from the hot path for 10-50x speedup.

**What's needed:**
- [ ] Replace BRK-based syscall trap with BL (branch-link) to trampoline
- [ ] BL-based TPIDR virtualization (no signals needed)
- [ ] Direct syscall dispatch without signal handler overhead
- [ ] Fork works naturally (no trampoline page needed)
- [ ] Benchmark suite

**Success criteria:** Within 2x of native Linux performance for CPU-bound workloads.

## Key Technical Challenges

### PAGEZERO (4GB)
macOS reserves 0x0-0x100000000 (PAGEZERO). Non-PIE Linux binaries that load at
0x400000 cannot work. Most modern binaries are PIE, but some older ones aren't.
**Mitigation:** Detect and warn; most container images use PIE binaries.

### Thread-Local Storage (TPIDR_EL0)
macOS clobbers TPIDR_EL0 on signal entry/return and during Darwin runtime calls.
We virtualize it by patching MSR/MRS instructions.
**For BL rewriting:** Use a dedicated register or global atomic for guest TPIDR.

### Fork Semantics
macOS fork() in signal context is broken. Current approach: return-into-trampoline.
**For BL rewriting:** Fork works naturally since syscalls aren't in signal context.

### 16KB Pages
macOS uses 16KB pages; Linux uses 4KB. mmap/mprotect alignment must account for this.
Some binaries have 4KB-aligned segments that need careful handling.

## Comparison with Docker Desktop

| Feature | Docker Desktop | fakelinux |
|---------|---------------|-----------|
| Approach | Linux VM (QEMU/HVF) | Direct execution + syscall emulation |
| Memory | 2-8GB for VM | Only what the binary uses |
| Startup | Seconds (VM boot) | Milliseconds |
| CPU overhead | ~5-10% (virtualization) | ~0% (native aarch64) |
| Disk | VM disk image | Just the rootfs |
| Networking | NAT through VM | Direct macOS sockets |
| File I/O | virtiofs (slow) | Direct macOS filesystem |
| Compatibility | Full Linux kernel | Syscall-level (growing) |

## Current State (as of 2026-04-11)

- ~100 syscalls implemented
- 26 tests passing
- Alpine rootfs works (busybox sh, id, date, wc, uname, pipes, subshells)
- Dynamic linking (glibc + musl)
- Fork + exec
- Signals with NEON save/restore
- Networking (TCP, UDP, Unix sockets, epoll)
- Working toward Python container support
