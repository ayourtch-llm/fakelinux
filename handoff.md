# Handoff — start here next session

_Last session: 2026-06-09 (session 6). Full story in `docs/diary.md`._

## What this project is

**fakelinux** runs unmodified ARM64 Linux binaries directly on macOS
(Apple Silicon) — no VM, no JIT recompiler. Guest code executes
natively; Linux-specific instructions are patched at load/mmap time and
emulated:

- `SVC #0` (syscalls) and `MSR/MRS tpidr_el0` → patched to `UDF`
  → SIGILL → `trap_handler` (src/trap.rs) emulates the syscall
  (src/syscall.rs translates Linux↔macOS semantics) or TLS access.
- x18-touching instructions (macOS reserves x18; Linux gcc uses it as
  scratch) → patched to `B <trampoline>` into MAP_JIT "islands"
  (src/x18_trampoline.rs); per-thread guest x18 lives in a pthread TSD
  slot read as `[TPIDRRO_EL0 + key*8]`. Instructions that can't be
  trampolined fall back to UDF + interpretive emulation driven by a
  decode table generated from the ARM ISA XML (build.rs → decoder.rs).
- ELF loading + runtime patching of newly-exec pages: src/loader.rs.
  Guest signals: src/signal.rs (Linux rt_sigframe on the guest stack).
  fork/clone/exec: src/thread.rs. Rootfs path mapping: src/rootfs.rs,
  `FAKELINUX_ROOT=<dir>`; `--container` virtualizes pid 1 (src/pidns.rs).

Build: `cargo build --release`. Typical run:

```sh
FAKELINUX_ROOT=ubuntu-rootfs ./target/release/fakelinux \
    --container ubuntu-rootfs/bin/bash -c 'uname -a'
```

Useful env vars: `FAKELINUX_TRACE=1` (syscall trace),
`FAKELINUX_TRACE_MMAP=1` (mmap/mprotect + fd paths),
`FAKELINUX_NO_X18_TRAMP=1` (force UDF emulation for x18, for bisecting).

The user prefers **TDD for bug fixes**: write the failing test first,
extract pure helpers to make logic testable (see tests in decoder.rs,
translate.rs, x18_trampoline.rs, trap.rs).

## Current state: apt-get install WORKS

`apt-get install -y vim` and a fresh `apt-get install -y less` complete
end-to-end on ubuntu-rootfs (download → unpack → postinst with
addgroup/adduser/useradd → configure), zero SIGSEGV/SIGBUS. The
long-standing "x18=0 after fork+exec" crash is fixed — it was never
about fork/exec.

Verify:

```sh
cargo test --release                  # 311 tests, 0 failures
FAKELINUX_ROOT=ubuntu-rootfs ./target/release/fakelinux \
    --container ubuntu-rootfs/usr/bin/apt-get install -y less
```

## What was fixed (commits c88ef94..ba9d2e6)

1. **`fix(x18)` c88ef94 — THE key invariant: the macOS kernel zeroes
   hardware x18 on any interrupt/context switch.** Guest x18 must never
   be held in hw x18, even for one instruction. Old trampoline did
   exactly that for ~3 instructions; preemption in the window → x18=0
   crash in liblzma's match finder (always the hottest trampoline, so it
   looked deterministic). New design: `decoder::substitute_gpr(instr,
   18, 17)` rewrites the instruction's x18 register fields to x17 (using
   the XML-generated `gpr_lsbs` table); the trampoline carries the guest
   value in x17 (kernel-preserved). 10 instructions, was 13.
   Also added: class filter (ADR/ADRP, load-literal, CBZ/TBZ, BR/BLR/RET,
   exclusives → UDF fallback — they can't execute at island PC).
2. **`fix(signal)` 8e17a20** — guest x18 (TSD) is now saved in the
   sigframe and restored at rt_sigreturn; handlers using x18 no longer
   clobber the interrupted code's x18.
3. **`fix(fcntl)` 83edcab** — flock `l_type` translation (Linux
   F_RDLCK/F_WRLCK/F_UNLCK = 0/1/2 vs macOS 1/3/2). Untranslated, a
   write lock became a macOS read lock on an O_WRONLY fd → EBADF →
   groupadd "cannot lock /etc/group" → postinst exit 82.
4. **`fix(net)` 78354f4** — inbound sockaddrs (connect/bind/sendto/
   sendmsg/sendmmsg) are copied to a local `sockaddr_storage` instead of
   mutated in guest memory. glibc syslog's `/dev/log` sockaddr lives in
   RODATA; the in-place store faulted, and with all signals blocked in
   trap context, macOS re-executed the store forever (100% CPU,
   unkillable, no dump). **General rule: never write to guest INPUT
   buffers from the trap handler.**

False alarm resolved: `X30_BECAME_HEAP!` diagnostics are noise — gcc on
aarch64-linux uses x30 (and x18) as ordinary scratch registers.

## Debugging tools added/learned

- Crash dump now identifies trampoline faults:
  `pc in trampoline island=... idx=... guest_orig_pc=...`
  (`find_trampoline_for_pc` decodes the trailing B).
- `FAKELINUX_TRACE_MMAP=1` now also logs file-backed mmaps (with fd
  path via F_GETPATH) and mprotect calls.
- `CURRENT_X18_INSTR` is cleared after successful emulation — the
  "emulating x18 instr=..." crash-dump line is no longer a stale red
  herring.
- Trick: a 100%-CPU hang that `kill -SEGV` can't dump = spin inside
  trap context (signals blocked). Bisect with raw `libc::write(2,...)`
  markers, not eprintln.
- Stale `/etc/*.lock` files in the rootfs (leaked when a run is
  SIGKILLed mid-postinst) are never reclaimed by shadow's liveness
  check (a lock containing vpid 1 always looks alive). Clean them
  manually: `rm -f ubuntu-rootfs/etc/{group,gshadow,passwd,shadow}.lock`

## Known remaining issues / next candidates

- **AF_UNIX sun_path is not translated into the rootfs** — guest
  connects/binds go to HOST paths (e.g. host `/dev/log`,
  `/var/run/nscd/socket`). Mostly harmless (ENOENT) but wrong; a guest
  binding a unix socket pollutes the host filesystem namespace.
- **Guests appear to survive SIGTERM** — plain `kill` of a fakelinux
  guest did nothing during debugging; only SIGKILL worked. Worth
  checking host-signal forwarding for unhandled-by-guest signals.
- **itimerval tv_usec**: macOS is i32 (+pad), Linux i64. Identical
  bytes for usec=0 (the common case); nonzero usec values are silently
  wrong in `do_setitimer`.
- **x16/x17 stack-frame red zone**: a signal landing inside a
  trampoline while SP is restored (slots 3–5) can clobber the saved
  x16/x17 below SP. Pre-existing, same as old design; documented in
  `emit()`.
- **SA_SIGINFO** still unsupported (x1/x2 = 0 in handlers) — see
  `docs/known-issues.md` for this and other medium/low items.
- **ET_EXEC (non-PIE) binaries** (Debian sid Python 3.13) still hit the
  macOS 4GB PAGEZERO limitation — fundamental; Ubuntu 24.04 is all PIE.
- dpkg warns `missing 'Description' field` at status line 212 — the
  rootfs `/var/lib/dpkg/status` carries scar tissue from old crashed
  runs; cosmetic.
- Git working tree contains many modified rootfs files (tttt-root/,
  ubuntu-rootfs/) — artifacts of test runs, intentionally uncommitted.

## Suggested next goals

1. `apt-get upgrade` on ubuntu-rootfs (bigger postinst surface:
   debconf, services, triggers).
2. Rootfs-translate AF_UNIX socket paths.
3. Run the C test suite (`tests/run_tests.sh`) against the new
   trampoline design for regressions.
4. Stress: parallel builds (`make -j`), git clone, python3 (PIE build).
