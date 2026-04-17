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

#### apt-get Hangs *(historical — fixed 2026-04-16)*

`apt-get update` used to hang intermittently after downloading the InRelease
files. As of commit 4b8f921 (signal-handler `sa_mask` fix) it completes
reliably and `apt-get install` works for at least the `file` package.

If you ever see something that looks like the old hang, check for stray
fakelinux processes from a previous run before assuming a new bug:

```bash
ps aux | grep fakelinux
pkill -9 -f fakelinux
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

## Session Notes

- [2026-04-13: Major debugging session](session-2026-04-13.md) — 12 bugs fixed
  (execve ENOENT, shebang scripts, symlink resolution, readlinkat fallback,
  signal preservation, CLONE_CHILD_SETTID, RwLock poisoning, heap-after-fork,
  Mach-O fallback, setpgid EACCES, xattr stubs, realpath). Detailed root cause
  analysis and debugging techniques for each.

- [2026-04-14: Fork child investigation & PID simplification](session-2026-04-14.md)
  — Container PID namespace simplified (only PID 1 virtual). TLS/stack overlap
  theory DISPROVED (canary always intact). The "corrupted saved LR" theory in
  this session was **also later DEBUNKED** (see 2026-04-16 entry below): the LR
  watch was monitoring the wrong stack slot for glibc 2.39's `_Fork` (which uses
  `sp+8`, not the older `__libc_fork`'s `sp+0xE8`). The actual root cause of the
  fork-child-runs-parent-code symptom turned out to be signal-handler concurrency,
  fixed in commit 4b8f921.

- **2026-04-15/16: XML-based decoder rewrite + apt-get unblocked**
  Massive cleanup and forward-progress session. See "2026-04-15/16 Session" below
  for full notes. Headlines:
  - Hand-rolled `INSTR_TABLE` and the `disarm64` crate dependency both gone.
    Decoder is now generated at build time from the authoritative ARM A64 XML
    spec (~2266 XML files vendored under `data/encoding/`).
  - 8 emulation bugs found by parallel audit agents and fixed TDD-style.
  - SIGILL handler `sa_mask` fix — the long-running "intermittent fork hang"
    was a single-thread signal-handler race on `mctx`, not a TPIDR/canary issue.
  - `apt-get update` works end-to-end.
  - `apt-get install -y --no-install-recommends file` installs 3/4 packages
    (libmagic-mgc, libmagic1t64, file). libc6 still blocks on debconf flock.

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

#### Fork child runs parent code — deep investigation (2026-04-13)

**Symptom**: After fork(), the child process runs the parent's code path
(close(5), write(6, config), read(7, InRelease)) instead of exec'ing gpgv.
This causes apt-get update to hang after downloading InRelease files.

**Investigation path** (many false leads before finding the real cause):

1. **Initial theory: execve fallback bug** — Commit 029107e fixed `do_execve`
   returning the current binary for non-existent files. This fixed one issue
   but the fork child problem persisted.

2. **Heap allocation after fork** — `format!`/`String` in `fork_trampoline_entry`'s
   child path allocated on the heap after `libc::fork()`. Rust's allocator inherits
   potentially-poisoned mutex state from the parent. Fixed by replacing all heap
   allocations with stack-buffer `Cursor::write_fmt`. Also fixed `do_fork()` which
   runs in signal handler context (not async-signal-safe).

3. **FD_CLOEXEC closed by macOS fork** — macOS's `fork()` atfork handlers close
   `FD_CLOEXEC` fds in the child. Linux does NOT (CLOEXEC only fires at exec).
   Guest code creates pipes with `O_CLOEXEC` expecting them to survive fork.
   Fixed by stripping CLOEXEC from all fds before `libc::fork()` and restoring
   in the parent after.

4. **CLONE_CHILD_SETTID not implemented** — glibc expects the kernel to write
   the child's TID to `pthread->tid` during clone. We now handle this in the
   fork trampoline child path.

5. **RwLock poisoning after fork** — `TPIDR_PATCHES_RUNTIME` (an `RwLock`) could
   be poisoned after fork if a panic occurred while holding it. Added recovery
   via `into_inner()` on poison error in `tpidr_lookup`.

> **⚠ DEBUNKED on 2026-04-16.** The "TPIDR overlaps stack canary" theory below
> was a false lead. The LR-watch instrumentation that produced the supporting
> evidence was monitoring the wrong stack slot — it watched `[guest_sp + 0xE8]`
> (the older `__libc_fork` saved-LR offset) but Ubuntu noble ships glibc 2.39
> whose `_Fork` saves LR at `[guest_sp + 8]`. Once the watch was moved to the
> correct slot it never fired. The actual root cause of the intermittent
> "child runs parent code" / nested-fork hang is signal-handler concurrency:
> SIGCHLD interrupting the SIGILL handler mid-mctx-write because the SIGILL
> handler was installed with `sigemptyset(&sa.sa_mask)`. Fixed in commit
> 4b8f921 by switching to `sigfillset`. See `docs/theory.md` for the analysis
> that led to the fix and the 2026-04-15/16 session below.
>
> Original (incorrect) theory preserved for context:

**ROOT CAUSE FOUND** *(later debunked — see callout above)*: glibc's `_Fork`
child path writes the robust list head to `[TPIDR - 0x668]` via
`STP x0, x0, [x6, #0xd8]` where `x6 = TPIDR - 0x740`. On real Linux, TPIDR
points to a TLS region far from the stack. Under fakelinux, the guest's
emulated TPIDR can point to glibc's TLS block allocated ON or NEAR the stack.
When TPIDR is exactly 0x740 bytes above `__libc_fork`'s SP, the STP overwrites
`[SP + 0xd8]` — the **stack canary** saved at `__libc_fork`'s entry.

The stack canary check at `c1d20` (`b.ne __stack_chk_fail`) fires, **skipping**
`mov w0, w19` (which would set the fork return to 0). `__libc_fork` returns
garbage to the caller, who sees non-zero and takes the parent path.

This is **intermittent** because it depends on the relative positions of TPIDR
and SP, which vary with ASLR, stack depth, and process state.

**Verification**: Added `FORK_SVC#N` tracing that logs the first 10 SVCs after
fork in each child. Working children show `nr=134` (rt_sigaction) as SVC#1
with x19=0 (fork return). Failing children show `nr=79` (fstatat) as SVC#1
with x19=pointer (inside __libc_fork's atfork handlers, x19 used as iterator).
The failing child's SVC#7 is `close(5)` — the parent code.

**Fix needed**: Ensure the guest's TLS/TPIDR region does not overlap with the
stack. Options:
- Allocate TLS at a fixed high address far from stack
- Detect and relocate TLS if it's too close to SP
- Intercept the dynamic linker's TLS setup

**Diagnostic traces added** (all guarded by `FAKELINUX_TRACE`):
- `SET_ROBUST`: w2 before/after set_robust_list handler
- `RESTORE`: x0 and pc from SavedRegs before asm restore
- `ASM_X0`: x0 value stored before restore_all_regs
- `FORK_SVC#N`: first 10 SVCs in fork child with nr, x0, x19, pc
- `EARLY_FD`: fd CLOEXEC flags immediately after libc::fork()
- `FORK_PROBE child`: fd type (P/F/C/S) and role (r/w/B)
- `FORK_CHILD vpid`: virtual PID state after fork
- `dup3()`: PID-annotated dup3 trace

#### Signal fixes (2026-04-13)

Three signal-related bugs were fixed (may not be root cause of hang but improve correctness):

1. **PENDING_SIGNALS not cleared after fork** (signal.rs, trap.rs): Child inherited parent's
   pending signals via COW. POSIX requires child's pending set to be empty.

2. **SIG_IGN not preserved across execve** (syscall.rs, main.rs): When do_execve() re-execs
   fakelinux, the new process had fresh statics with all GUEST_SIGACTIONS = SIG_DFL. Now
   encodes SIG_IGN bitmask in `FAKELINUX_SIGIGN` env var, read on startup.

3. **Signal mask not inherited across execve** (main.rs): GUEST_SIGMASK reset to 0 on re-exec.
   Now propagated via `FAKELINUX_SIGMASK` env var.

**Workaround (no longer needed since 2026-04-16, but harmless)**:
```bash
FAKELINUX_ROOT=./ubuntu-rootfs timeout 120 ./target/debug/fakelinux --container ./ubuntu-rootfs/usr/bin/apt-get update
```

## 2026-04-15/16 Session — XML decoder, signal-race fix, apt-get install

This was a long, multi-day push that took fakelinux from "apt-get update
sometimes hangs" to "`apt-get install file` actually puts a working `file`
binary on disk". A lot was rewritten or thrown out; capture the highlights
here so they don't get lost.

### Decoder rewrite from authoritative ARM XML spec

**Why**: Several debug sessions in early April kept finding cases where the
hand-rolled `INSTR_TABLE` (and the `disarm64` crate fallback) misclassified
instructions referencing x18, leading to silent miscompiles and corrupted
state. Writing one more ad-hoc pattern on top of the previous ones felt like
the wrong direction.

**What changed**:
- Vendored the ARM A64 ISA XML spec (~2266 instruction XML files) into
  `data/encoding/`.
- New `build.rs` (~430 lines) parses every XML at build time, extracts
  mask/value/GPR-field information from `<regdiagram>`, derives an
  `EmulClass` from the `psname` decode path
  (e.g. `A64.dpimm.addsub_imm.ADD_32_addsub_imm` → `EmulClass::AddSubImm`),
  and emits `generated_x18_table.rs` and `generated_x18_tests.rs` into `OUT_DIR`.
- `src/decoder.rs` shrank from ~2062 lines to ~200 — now just `EmulClass`,
  `from_u8`, `references_x18`, `decode_emul_class`, and `include!`s of the
  generated table.
- `Cargo.toml`: removed the `disarm64` and `disarm64_defn` deps; added
  `roxmltree` as a build-dependency only.
- `src/trap.rs::emulate_x18_instruction()` was refactored from a ~740-line
  if/else chain into a `match` on `EmulClass` with one named handler per
  class. The handlers (`emul_addsub_imm`, `emul_logical_imm`, `emul_ldp_stp`, …)
  contain the same semantics as the old branches, just extracted and
  individually testable.

**Bugs found during the rewrite** (all fixed TDD-style — tests first):
Three audit subagents combed the new handlers in parallel and surfaced 8
discrete bugs (signed loads emulated as stores, EXTR `lsb=0` returning the
wrong operand, ORR with `Rd=31` discarding instead of writing SP, dead
conditional in pre/post-index writeback, and others). Each is now covered
by a regression test in `src/trap.rs`'s `tests` module.

### Literal-pool detection (don't patch data as if it were code)

Two distinct mechanisms feed `find_literal_pools` in `src/loader.rs`:

1. **ADR + post-inc-load pattern**: detects `ADR x?, #imm; LDR ?, [x?, #imm]!`
   constructs that mark the start of an embedded data table.
2. **SHA-256 K-table fingerprint scan**: looks for the four-word signature
   `0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5` in `.text` and excludes
   the surrounding 256 bytes from x18/TPIDR patching.

The fingerprint scan was added because libgcrypt loads the K constants
through the GOT rather than via an ADR-relative literal pool, so the first
mechanism alone missed it. Without this, the K constants (which happen to
look like ARM instructions when scanned as opcodes) were being "patched"
and apt's signature verification corrupted SHA-256 outputs.

See `feedback_literal_pools.md` in the assistant memory for the rule of
thumb: **anytime hashing breaks, suspect a literal pool that wasn't
detected**.

### The big one — signal-handler `sa_mask`

Symptom: nested forks (e.g. `dash -c "echo \$(echo \$(echo deep))"`) hung
about 15% of the time. Earlier theories (TPIDR overlapping the stack canary;
LR corruption inside `__libc_fork`) were debunked once the LR-watch
instrumentation was fixed for glibc 2.39's `_Fork` (which saves LR at
`sp+8`, not the older `sp+0xE8`).

The actual race was between two signal handlers, both running on the same
thread, both mutating macOS's `mctx`:

- `trap_handler` (SIGILL from a UDF) restores guest registers, redirects PC.
- `signal_forwarder` (SIGCHLD when a child exits) builds a sigframe and
  redirects PC into the guest's signal handler.

`install_trap_handler()` was using `sigemptyset(&sa.sa_mask)`, so SIGCHLD
could interrupt `trap_handler` mid-mctx-write — for nested forks, multiple
SIGCHLDs arrive close together, blowing up the race window. Switching to
`sigfillset(&sa.sa_mask)` blocks all other signals while `trap_handler` runs;
they get delivered cleanly via `sigreturn`.

**Verification**: 0/50 hangs after the fix (was 3/20 before). `apt-get
update` started completing reliably immediately after this commit.

`docs/theory.md` (added the same day) walks through the analysis that pointed
at "shared mutable state across handlers" as the right place to look. The
theory document was right about the mechanism even though the *original*
hypothesis (multi-thread race on FORK trampoline state) named the wrong
suspect — the actual race was single-thread signal-handler interleaving.

### `apt-get install file` — getting through dpkg

Once update worked, install surfaced its own crop of bugs. In order of
discovery:

1. **`/tmp` was not translated** under `FAKELINUX_ROOT`. The translator
   passed `/tmp` straight through to the host, which on macOS becomes
   `/private/tmp` — leaking host files into the guest and putting dpkg's
   `/tmp/apt-dpkg-install-XXX/` staging directory on the wrong filesystem.
   Now translated like any other path in full-rootfs mode (kept as-is in
   sysroot-only mode for backward compat).
2. **SIMD&FP `LDP/STP` via x18** (`emul_ldp_stp`). The decoder correctly
   classified `LDP q0, q1, [x18]` (`0xAD400640`) as `LdpStp`, but the
   handler only knew about the GPR variant — it wrote into x0/x1 instead
   of v0/v1, corrupting tar's stack inside dpkg-deb. Symptom:
   `tar: This does not look like a tar archive`. Now distinguishes the
   V flag (bit 26) and routes to `mctx.ns.v[]` for the SIMD case, with
   element width derived from `opc` per the A64 spec (S/D/Q for V=1).
3. **`utimensat` `AT_SYMLINK_NOFOLLOW` flag value** is `0x100` on Linux
   but `0x20` on macOS. Without translation macOS silently followed the
   symlink. Also rewrote `do_utimensat` to delegate directly to macOS's
   native `utimensat` (available since 10.13) instead of reimplementing
   `UTIME_NOW`/`UTIME_OMIT` on top of `utimes`.
4. **Final-component symlink resolution at the rootfs translation layer**.
   `effective_path_ptr` always walked the full path, resolving every
   symlink — which is wrong for syscalls that operate on the link itself
   (`rename`, `unlink`, `link`, `utimensat`-NOFOLLOW). dpkg stages files
   as `*.dpkg-new` symlinks pointing at not-yet-extracted targets, so
   resolving the final component dereferences a dangling link → ENOENT.
   Added `translate_path_nofollow` (translates parent components but
   leaves the basename untouched) and `effective_path_ptr_nofollow`,
   wired into `SYS_UNLINKAT`, `SYS_RENAMEAT`, `do_renameat2`, `do_linkat`
   (when `AT_SYMLINK_FOLLOW` is *not* set), and `do_utimensat` (when
   `AT_SYMLINK_NOFOLLOW` is set).
5. **`do_renameat2` was passing untranslated guest paths straight to
   macOS** — a long-standing oversight that became visible only once
   the other fixes let dpkg get this far. Now uses the nofollow variant.
6. **`PATH` default** widened from `/usr/bin:/bin` to
   `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` so
   dpkg-trigger / dpkg-divert and other `/usr/sbin` tools resolve when
   maintainer scripts invoke them by basename.
7. **PTY ioctls** `TIOCSPTLCK` (`0x4004_5431`) and `TIOCGPTN`
   (`0x8004_5430`) added so `unlockpt()` / pty allocation works.

**Result**: `apt-get install -y --no-install-recommends file` reaches
`Status: install ok unpacked` for libmagic-mgc, libmagic1t64, and file.
`/usr/bin/file` runs and correctly identifies ELF binaries, ASCII text,
etc. inside the container.

```
$ FAKELINUX_ROOT=ubuntu-rootfs ./target/release/fakelinux \
    --container ubuntu-rootfs/bin/bash -c 'file /etc/passwd /usr/bin/bash'
/etc/passwd:   ASCII text
/usr/bin/bash: ELF 64-bit LSB pie executable, ARM aarch64, ...
```

**Still blocked**: libc6 — its `preinst` exits 1 because debconf's
`fcntl(F_SETLK)` on `/var/cache/debconf/config.dat` returns EAGAIN even on
a fresh process tree. Likely a `linux_flock_to_mac` struct-layout quirk
(Linux puts `l_type`/`l_whence` first in `struct flock`, macOS puts them
last). Tracked in the assistant memory under `project_apt_install_status.md`.

### Commits from this session (most recent first)

```
a74d28d  fix(loader): include /sbin and /usr/sbin in default PATH
be987a9  fix(rootfs/syscall): translate /tmp; honor symlink-nofollow at translation layer
cde26fc  fix(emul): handle SIMD&FP LDP/STP via x18 (V=1 variant)
4b8f921  fix: block other signals during SIGILL handler — fixes nested fork race
0179eea  docs: add fork concurrency theory analysis
c2d96b5  debug: fix LR watch address for glibc 2.39's _Fork (was watching wrong slot)
84cfdc0  fix: detect SHA-256 K table by fingerprint (catches libgcrypt's K constants)
5c5ebbc  fix: keep IN_TRAP=true during deliver_pending_to_guest to prevent race
edb4e3e  fix: literal pool detection — ADR + post-inc-load pattern
e4c2233  feat: complete table-driven x18 detection, eliminate fallback code
513aea8  feat: improve x18 detection coverage in decoder.rs
4d5af9e  feat: integrate decoder.rs as single source of truth for x18 detection
```

Plus several decoder-classification commits earlier in the chain
(`feat(decoder): add unified emulate function with EXTR support`, etc.).

### Handoff — start here next session

**Goal**: get libc6 to install so `apt-get install` is unblocked for any
package that depends on a newer glibc.

**Symptom**: `apt-get install -y --fix-broken` reaches libc6's preinst,
which exits 1 with this debconf error:

```
debconf: DbDriver "config": /var/cache/debconf/config.dat is locked
        by another process: Resource temporarily unavailable
```

EAGAIN/EWOULDBLOCK on a freshly-spawned process tree means the
`fcntl(F_SETLK)` translation is most likely returning a stale
"already locked" answer rather than acquiring the lock.

**Where to look first**:

- `src/syscall.rs::do_fcntl` (the `F_GETLK / F_SETLK / F_SETLKW` arm,
  around line 1073).
- `src/translate.rs::linux_flock_to_mac` and `mac_flock_to_linux`. The
  `struct flock` layouts differ between Linux and macOS:

  ```c
  // Linux (aarch64):              // macOS (aarch64):
  short  l_type;                   off_t  l_start;
  short  l_whence;                 off_t  l_len;
  off_t  l_start;                  pid_t  l_pid;
  off_t  l_len;                    short  l_type;
  pid_t  l_pid;                    short  l_whence;
  ```

  If our translator copies field-by-field assuming the Linux order,
  macOS will see garbage `l_type` (likely `F_WRLCK`-equivalent) on the
  query call and return EAGAIN even when the file is unlocked.

**How to verify cheaply**:

```
pkill -9 -f fakelinux
cp /tmp/libc6_inspect/preinst ubuntu-rootfs/tmp/preinst.sh
chmod +x ubuntu-rootfs/tmp/preinst.sh
FAKELINUX_TRACE=1 FAKELINUX_ROOT=ubuntu-rootfs \
    ./target/release/fakelinux --container ubuntu-rootfs/bin/bash \
    -c '/tmp/preinst.sh install' 2>&1 | grep -E 'fcntl|flock|F_SETLK'
```

The libc6 .deb is at `ubuntu-rootfs/tmp/libc6_2.39-0ubuntu8.7_arm64.deb`
and was extracted to `/tmp/libc6_inspect/` during the previous session.

**Watch out for** (real but probably out of scope for this fix):
- Once libc6 installs, dpkg may run more `.dpkg-new` rename storms — the
  nofollow translation work landed on 2026-04-16 should still hold up,
  but worth re-running the full suite afterwards.
- The `Description` field warning when parsing `/var/lib/dpkg/status` is
  cosmetic; ignore unless it starts blocking something.

**Recent state for memory**: `project_apt_install_status.md` and
`MEMORY.md` are both up to date. The signal-race write-up
(`project_nested_fork_race.md`) and the LR-corruption-debunk
(`project_fork_lr_corruption.md`) document the dead-end theories — read
those before re-investigating "fork is broken" symptoms, you'll save time.

### What's worth carrying forward

- Whenever a "race" appears on a single-threaded process, ask first
  whether two signal handlers can interrupt each other. `sa_mask` is
  cheap insurance for any handler that touches `mctx` or shared statics.
- For signal handlers that mutate `mctx`, `sigfillset(&sa_mask)` should
  be the default; only relax it when you've proven the handler is
  re-entrant.
- Path translation isn't a single thing. Distinguish syscalls that
  operate on the symlink (`rename`/`unlink`/`lstat`/`utimensat`-NOFOLLOW)
  from those that operate on the target (`open`/`stat`). Resolving the
  final component for the former silently breaks dpkg-style staging.
- AT_* flag values are not portable. `AT_SYMLINK_NOFOLLOW` is `0x100`
  on Linux and `0x20` on macOS; `AT_SYMLINK_FOLLOW` happens to match,
  but don't rely on coincidence — translate explicitly.
- When a hash function corrupts output, suspect a literal pool that the
  patcher mistook for code. Two detection mechanisms (ADR-pattern and
  fingerprint scan) catch different cases.

### DNS Resolution Fails

Create `/etc/resolv.conf` in the rootfs:

```bash
echo "nameserver 8.8.8.8" > ubuntu-rootfs/etc/resolv.conf
```

## 2026-04-17 Session — env propagation fix, zstd/libc6 deep-dive

Continued from the 2026-04-15/16 handoff, which had hypothesised a
`struct flock` layout bug behind the libc6 preinst failing with
`debconf: DbDriver "config": config.dat is locked by another process`.

### The flock theory was wrong

First thing this session: `grep`'d the guest, debconf uses Perl
`flock($fh, LOCK_EX | LOCK_NB)` — the BSD `flock(2)` syscall, not
`fcntl(F_SETLK)`. So any layout issue in `linux_flock_to_mac` couldn't
have caused the symptom. Saved some time for the next person:
**always re-check what the failing caller is actually invoking** rather
than trusting a handoff hypothesis at face value.

### Real root cause — env was not crossing execve

Tracing with `FAKELINUX_TRACE=1` showed two back-to-back debconf
frontends being launched: an outer one (PID A) that cleanly locked
`config.dat`, then a child (PID B) that re-exec'd `/usr/share/debconf/frontend`
and raced A for the same lock. Debconf is supposed to detect the outer
frontend via `$ENV{DEBIAN_HAS_FRONTEND}=1` and connect via inherited fds,
but the variable wasn't propagating.

The reason sat in two places:

1. **`src/syscall.rs::do_execve`** was passing the *host* libc `environ`
   into `libc::execve(self_exe, argv, environ)`, throwing away the
   guest's envp. Any guest-set env var (perl's `$ENV{DEBIAN_HAS_FRONTEND}`,
   bash's `export`, etc.) was lost across the re-exec boundary.
2. **`src/loader.rs::setup_stack`** was hardcoding the fresh guest's
   initial envp to exactly `[PATH, HOME, TERM]`, so even after fixing (1)
   the newly-loaded binary only saw three vars.

Both fixes went in TDD-first (per user's explicit preference this
session):

- `merge_envp(guest_env, overrides) -> Vec<CString>` in `syscall.rs`,
  with 6 unit tests covering DEBIAN_HAS_FRONTEND pass-through, FAKELINUX_*
  overrides replacing/adding/removing, and first-wins dedup.
- `build_guest_env(host_env) -> Vec<CString>` in `loader.rs`, with 5
  tests for DEBIAN_HAS_FRONTEND propagation, FAKELINUX_* stripping, and
  PATH/HOME/TERM defaults when the host didn't set them.

All 161 unit tests pass afterwards (148 → 161, +13 new). Committed as
`2065aea fix(exec): propagate guest env through execve and into
freshly-loaded guest`.

Regression check: `apt-get install file` still reaches
`Status: install ok unpacked` for libmagic-mgc, libmagic1t64, and file.
libc6's preinst now gets past the debconf step, surfaces the expected
pre-existing `dpkg-divert` clash on `/var/lib/dpkg/diversions` (state
issue, not a fakelinux bug), and `apt --fix-broken install` exposes the
NEXT blocker described below.

### New blocker — libzstd "Data corruption detected" on libc6 unpack

`apt --fix-broken install` and `dpkg-deb --contents libc6....deb` both
die deterministically at the exact same file (`./usr/lib/.../gconv/libCNS.so`)
with:

```
dpkg-deb (subprocess): decompressing archive 'libc6_...deb' member 'data.tar':
    zstd error: Data corruption detected
/usr/bin/tar: Unexpected EOF in archive
```

Architecture of dpkg-deb's extraction (confirmed from trace):

- PID A (`dpkg-deb` main) opens the `.deb`, lseek's past the ar headers,
  forks twice.
- PID B (pump, forked from A) reads raw `data.tar.zst` bytes from fd=3
  and writes them unmodified to pipe fd=5.
- PID C (decompressor, forked from A) reads compressed bytes from
  pipe fd=4 (the other end of B's pipe), calls
  `ZSTD_decompressStream` in-process, writes decompressed tar to pipe
  fd=6.
- PID D = `/usr/bin/tar -tvf -`, reads decompressed tar from stdin.

Added two debug knobs to the syscall layer —
`FAKELINUX_DUMP_WRITE_FD=<fd>` and `FAKELINUX_DUMP_READ_FD=<fd>` — that
append every successful byte of a matching read/write to
`/tmp/pipe_dump_*_pid<pid>_fd<fd>.bin`. Used them to build a clean
evidence chain:

- The pump's writes on fd=5 (1,277,952 bytes before EPIPE) have
  `sha256` identical to the corresponding byte range of
  `data.tar.zst` in the `.deb`. Pump is reading and forwarding
  correctly.
- The decompressor's reads on fd=4 (1,179,675 bytes before giving up)
  are a perfect prefix of the pump's writes (`cmp` reports EOF on the
  shorter file, not a mismatch). Pipe is carrying correct data.
- Host `zstd -d` fed the exact 1,179,675-byte prefix decompresses to
  19.1 MB and then exits with `/*stdin*\ : Read error (39) : premature
  end`. That's the expected end-of-stream error for an incomplete
  zstd frame — NOT `Data corruption detected`.
- Guest libzstd fed the same bytes produces 18.9 MB of decompressed
  output (a valid prefix of host zstd's 19.1 MB), then reports
  `Data corruption detected` instead of `premature end`.

Same bytes in, different error path out. That's the smoking gun but
not a fix. Ruled out as the cause:

- x18 patching — rerunning with `FAKELINUX_NO_X18=1` reproduces the
  symptom identically.
- Signal interference — no SIGCHLD / signal-forwarder activity between
  the last successful read and the corruption report.
- Generic pipe integrity — `cat file | cat | cat | sha256sum` on a
  5 MB random file produces a matching hash inside the guest.

What still seems plausible but wasn't proved in-session:

1. Memory corruption inside libzstd's `DCtx` / Huffman tables via a
   mis-emulated x18-relative store. The `emul_ldr_str_reg_offset`
   path handles `STR Xt, [X18, Xm, LSL #N]` — if any dispatch goes
   through a buggy variant, we'd scribble on libzstd's heap without
   touching input bytes. Open question: are x18-relative stores ever
   targeting addresses inside libzstd's allocated context struct?
   Next session should add a trap that records every x18-relative
   STORE destination in PID C and cross-reference against libzstd's
   malloc ranges.
2. Short-read interleaving. The reads just before failure follow
   libzstd's well-known `+3`-byte lookahead-padding pattern:
   `65539 requested → 32744 returned`, then `32795 requested → 32768`,
   then `27 requested → 27`. The sequence is legal and the bytes are
   valid, but there's a chance an older libzstd (1.5.5 ships in noble)
   has a state-machine edge-case that Linux's kernel pipe semantics
   avoid but macOS's don't. Would need a real-Linux cross-check with
   the same captured prefix.
3. Fork semantics around libzstd state. dpkg-deb forks AFTER zstd
   helpers are initialised in the parent; our fork hooks might not
   preserve something libzstd relies on. No concrete suspect, but
   worth instrumenting.

While at it, broadened `fakelinux_env_overrides()` to forward every
`FAKELINUX_*` host variable through the execve chain rather than a
hardcoded allowlist, so the new `FAKELINUX_DUMP_*` knobs (and any
future debug envs) keep working across re-execs without needing code
changes. `build_guest_env` already strips `FAKELINUX_*` before handing
to the guest, so no supervisor-internal state leaks.

Commits from this session:

```
f00d98c  debug(syscall): FAKELINUX_DUMP_{READ,WRITE}_FD pipe-byte dumpers; broaden FAKELINUX_* forwarding
2065aea  fix(exec): propagate guest env through execve and into freshly-loaded guest
```

### Handoff — start here next session

**Goal**: unblock `dpkg-deb --contents libc6....deb` inside fakelinux.
Everything upstream (env propagation, debconf, file unpack) now works.

**First experiment**: add a store-destination tracer to
`emul_ldr_str_reg_offset` (and friends in `src/trap.rs`) that, when
`FAKELINUX_TRACE_X18_STORES=1` is set, logs every `(pc, base_reg,
addr, value)` on emulated stores. Run it for the dpkg-deb failure and
check for stores landing inside the heap range libzstd uses for its
DCtx (you can dump the heap layout from `/proc/self/maps` in the guest).

**Cheap cross-checks**:
- Rebuild the test on a real Linux ARM64 box using the captured
  1,179,675-byte prefix (`/tmp/pipe_dump_read_pid*_fd4.bin`) — does
  native libzstd 1.5.5 also say "Data corruption" or "premature end"?
  If "premature end" there too, the bug is 100% fakelinux-specific.
- Try `dpkg-deb --fsys-tarfile libc6....deb > /tmp/out.tar` inside
  the guest — different code path through dpkg-deb, same libzstd.
  If it fails at the same offset, libzstd is definitely seeing
  corrupt state regardless of the output pipe.

**State for memory**: the full narrative is in
`project_libc6_zstd_corruption.md` (and `MEMORY.md` indexes it).
Reproducer, dump-file layout, and what's already been ruled out are
there — read them before instrumenting, so you don't repeat the same
experiments.

---

## 2026-04-17 (session 2) — x18 store tracer experiment

### What was done

Added `FAKELINUX_TRACE_X18_STORES=1` env knob to `src/trap.rs`.
When enabled, every emulated x18-relative store logs `(pid, pc,
base_reg, addr, val, size, x18_value)` to stderr.  Also snapshots
`/proc/self/maps` once per process to `/tmp/x18_maps_pid<pid>.txt`.
Covers all 5 store paths: `emul_ldr_str_unsigned_imm`,
`_unscaled`, `_prepost`, `_reg_offset`, and `emul_ldp_stp`.

Reproduced the dpkg-deb libc6 "Data corruption detected" failure
with the tracer on.  14086 stores logged for the decompressor
process (pid 97519), across 5 distinct instruction PCs.

### Key finding: the 2147-x18 segment is **libzstd** (not libc)

The runtime patch block with 2147 x18 patches (size 0xb0090) is
**libzstd.so.1.5.5** — confirmed by matching the instruction at
offset 0x86d90 against the libzstd binary on disk.

libzstd uses x18 as a **general-purpose data register** for
Huffman/FSE decode table construction (NOT for TLS as previously
assumed).  The hot instruction is:

    STR x1, [x18, x2, LSL #3]   ; libzstd+0x86d90

This is a tight loop that stores computed 8-byte entries (replicated
16-bit {nbBits, symbol} values like 0xba09ba09ba09ba09) into
heap-allocated decode tables, using x18 as the table base pointer
and x2 as the index.

12313 of 14086 total stores hit this single PC.  190 unique
destination addresses spanning ~1.5 KB of heap (0x5000cf3bc–
0x5000cf9a4), with 18 unique x18 base values — consistent with
~65 block iterations, each rebuilding a 256-entry table.

The values are 100% deterministic across runs (identical addresses,
values, and ordering), so the emulation is at least consistent.

### FAKELINUX_NO_X18=1 is NOT a valid control

The previous session noted "FAKELINUX_NO_X18=1 still reproduces the
same symptom", concluding x18 emulation was ruled out.

**This conclusion is incorrect.**  When NO_X18=1, libzstd's x18-
relative stores/loads execute natively using macOS's x18 (the
reserved TLS pointer), NOT the guest's heap-allocated table pointer.
This causes SIGSEGV at pc=0x0 (null function pointer from corrupted
TLS data) — a **completely different failure** from the zstd "Data
corruption detected" error.

### What the stores look like

All base=x18 stores land in the heap (0x5000c*):
- 12313 stores at 190 unique heap addresses (Huffman table writes)
- 1773 stores at stack addresses (register spills + SIMD copies)

The store emulation path (`emul_ldr_str_reg_offset` with
STR reg offset) reads x18 from thread storage (`get_thread_x18()`),
computes addr = x18 + extend_reg(x2, LSL, 3), reads x1 from
mcontext, stores via `store_mem`.  Code review shows no bug.

### Other PCs

| PC offset | Count | Instruction | Notes |
|-----------|-------|-------------|-------|
| libzstd+0x86d90 | 12313 | STR x1, [x18, x2, LSL #3] | Huffman table writes |
| libzstd+0x4ee60 | 400 | STP q0, q1, [x18] | SIMD pair to stack |
| libzstd+0x5626c | 686 | STP x22, x18, [sp, #...] | Register spill |
| libzstd+0x562e8 | 686 | STP x0, x18, [sp, #...] | Register spill |
| ld-linux+0x8cfc | 1 | STR ..., [sp] | ld-linux init |

### What's still open

1. **Emulation correctness** — the stores LOOK correct but we
   haven't verified the VALUES against native libzstd output.
   A unit test exercising `STR x1, [x18, x2, LSL #3]` emulation
   with known inputs would help.

2. **Load-side correctness** — we only traced stores.  If
   `LDR xN, [x18, xM, LSL #3]` returns wrong data, the
   decompressor would see "corruption" in its own table.

3. **Missed patches** — there are ~2975 instructions in libzstd's
   .text with 18 in register fields (naive count), of which 2147
   were patched.  The ~800 delta is likely instructions where "18"
   is in an immediate or non-GPR field (correctly ignored by the
   decoder), but this needs verification.

4. **Non-x18 hypotheses remain viable**: fork semantics around
   libzstd state, short-read interleaving at block boundaries, or
   a mmap/brk overlap.

### Handoff — start here next session

**Goal**: same as before — unblock dpkg-deb libc6 inside fakelinux.

**Most productive next experiment**: add a LOAD tracer (symmetric to
the store tracer) for x18-relative loads in the decompressor.  If a
load returns the wrong value from a correctly-written table, we've
found the bug.  Check `emul_ldr_str_reg_offset` LDR path for any
size/sign-extension issues.

**Quick win to try**: run `dpkg-deb --fsys-tarfile libc6...deb >
/tmp/out.tar` inside the guest (different dpkg-deb code path, same
libzstd).  If it fails at the same offset, libzstd is definitely the
problem.  If it works, the issue is in the tar pipe plumbing.

**State for memory**: updated `project_libc6_zstd_corruption.md` with
the finding that x18 emulation is NOT ruled out and libzstd uses x18
as a data pointer.

Commits from this session:

```
<pending>  debug(trap): FAKELINUX_TRACE_X18_STORES store-destination tracer + procfs snapshot_maps
```
