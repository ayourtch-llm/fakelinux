# Handoff — start here next session

_Last update: 2026-06-09 (session 7, mid-session context refresh). Full story in `docs/diary.md`._

## What this project is

**fakelinux** runs unmodified ARM64 Linux binaries directly on macOS
(Apple Silicon) — no VM, no JIT recompiler. Guest code executes
natively; Linux-specific instructions are patched at load/mmap time and
emulated:

- `SVC #0` (syscalls) and `MSR/MRS tpidr_el0` → patched to `UDF`
  → SIGILL → `trap_handler` (src/trap.rs) emulates the syscall
  (src/syscall.rs translates Linux↔macOS semantics) or TLS access.
- x18-touching instructions → `B <trampoline>` into MAP_JIT islands
  (src/x18_trampoline.rs); guest x18 lives in pthread TSD
  `[TPIDRRO_EL0 + key*8]`. NEVER hold guest state in hw x18 (kernel
  zeroes it on interrupts).
- ELF loading: src/loader.rs. Guest signals: src/signal.rs.
  fork/clone/exec: src/thread.rs. Rootfs mapping: src/rootfs.rs.
  POSIX timers: src/timers.rs (NEW this session).

Build: `cargo build --release` (remember: `cargo test` does NOT rebuild
the binary — build explicitly before re-running guests!). Run:

```sh
FAKELINUX_ROOT=ubuntu-rootfs ./target/release/fakelinux \
    --container ubuntu-rootfs/bin/bash -c 'uname -a'
```

Env: `FAKELINUX_TRACE=1` (syscalls + new timer trace), `FAKELINUX_TRACE_MMAP=1`.
User prefers **TDD**: failing test first, extract pure helpers.
Tests: `cargo test --release` — 330 tests, 0 failures as of now.

## Session 7 so far (commit 06fe1aa-ish, after 8c79705)

Goal: make interactive vim work; then python3.

### Fixed (committed: "fix(mprotect): round outward for write grants…")

1. **vim SIGBUS on first keypress** — root cause: `do_mprotect`
   (src/syscall.rs) rounded the range INWARD to 16KB macOS pages.
   glibc pthread_create mprotects the new thread stack RW with
   unaligned end (addr=...000, len=0x21a60); the tail 0x1a60 bytes
   (thread descriptor at stack top!) stayed PROT_NONE → SIGBUS.
   Fix: `mprotect_align_range` helper — write-granting mprotect
   rounds OUTWARD, PROT_NONE/read-only rounds inward (RELRO safety).
   Fallback to inward if outward fails (ENOMEM past mapping).
2. **vim 100% CPU hang** — glibc timer helper thread busy-spun on
   ENOSYS `rt_sigtimedwait` (syscall 137, 8.4M calls!). Implemented:
   polls PENDING_SIGNALS + timers::pop_queued_siginfo every 10ms,
   honors timeout, writes Linux siginfo (si_signo@0, si_code@8,
   si_tid@16, si_overrun@20, si_value@24).
3. **vim E1286 "Could not set timeout"** on every command —
   timer_create was ENOSYS. Implemented POSIX timers
   (src/timers.rs): syscalls 107/108/110/111, dispatcher thread,
   RT-signal (>=32) expiry → queue SI_TIMER siginfo + PENDING bit
   (consumed by glibc helper in rt_sigtimedwait); classic signals →
   host kill(). Has unit tests for pure helpers.
4. **Crash-dump visibility**: signal_forwarder now logs
   "forwarding SIGBUS to guest handler: pc=… far=… instr=…" (first 8)
   — guest handlers (like vim's) used to swallow our crash dumps.

### vim — DONE (commit aaa62ce, user-confirmed on real terminal)

Final bug: syscall 169 gettimeofday passed the guest ptr straight to
macOS, whose tv_usec is **i32** (writes 12 bytes); Linux aarch64
expects i64 → stale garbage in the high half → vim's termresponse
deadline never expired (pselect timeouts of 545460s!) → ALL redraws
deferred: blank startup screen, insert-mode typing invisible until
ESC, Ctrl-C looked broken. Diagnostic that cracked it: trace showed
read(0) of typed keys but ZERO write(1) calls. Fix: do_gettimeofday
converts explicitly; tests gettimeofday_writes_full_i64_usec +
setitimer regression. NOT timers, NOT pselect sigmask.
**Bug class to sweep later: macOS suseconds_t i32 — check getrusage
(timeval pairs ~src/syscall.rs:2455).**

Note: ../mcp-pty-server now supports [ESC] (alias of [ESCAPE],
commit 247e02b there); the tttt server may need the same treatment.

### Old vim notes (kept for reference)

`vim.basic` now: starts, edits, no crash, no E1286, timer helper
parked at 0% CPU. **Remaining bug (user-confirmed on real terminal):
initial screen is NOT drawn after startup until you enter
insert/append mode; once in insert mode everything draws fine.**
In normal mode after startup vim sits in a pselect+clock_gettime
poll loop reading keys but never writing output (verified via
FAKELINUX_TRACE: read(0) happens, zero write(1) after).

Hypothesis ranked:
1. vim waits on POSIX-timer expiry that never fires / fires wrong —
   I JUST added timer tracing (timer_create/settime/FIRE lines under
   FAKELINUX_TRACE, committed). NEXT STEP: run
   `FAKELINUX_TRACE=1 TERM=vt100 … vim.basic /tmp/test.txt`, watch
   `grep "timer" log` — does settime get a FIRE? Does vim redraw
   after? Compare timings.
2. vim waiting for terminal query responses (ESC[>c, OSC 10/11,
   ESC[6n) — on real terminal these ARE answered, and user still sees
   missing initial draw, so this is NOT the whole story. (In tttt pty
   these are never answered; can't send raw ESC byte via
   tttt_pty_send_keys — no [ESC] token; Ctrl+C substitutes for ESC to
   leave insert mode.)
3. pselect sigmask bug: do_pselect6 passes the guest's LINUX sigset
   ptr directly as a macOS sigset_t* — wrong layout/numbering.
   Suspicious but probably not the redraw bug (x5=0 in vim's calls).

Test loop (use tttt pty-2, kill leftovers first):
```sh
pkill -9 -f "fakelinux --container"; rm -f ubuntu-rootfs/tmp/.test.txt.sw*
clear; FAKELINUX_TRACE=1 TERM=vt100 FAKELINUX_ROOT=ubuntu-rootfs \
  ./target/release/fakelinux --container ubuntu-rootfs/usr/bin/vim.basic \
  /tmp/test.txt 2>/tmp/vim-tN.log
```
vim's /tmp = ubuntu-rootfs/tmp (swap files live THERE).
PTY wait pattern: tttt_pty_wait_for_idle, then send keys.

### python3 (task #3, IN PROGRESS, untouched since analysis)

`ubuntu-rootfs/usr/bin/python3.12` is **ET_EXEC** (Ubuntu builds
python no-pie!) → relocated to 0x700400000 → SIGSEGV exit 139 early.
Crash analysed: pc in libc strcpy-ish loop, instr 0xf86a6803 =
`LDR x3, [x0, x10]`, fault_addr = x0+x10 = 0x701f60 — an UNRELOCATED
pointer that arrived via register arithmetic (base+index), probably
materialized by MOVZ/MOVK literals the data-scan can't see.
The lazy-reloc Case 2 in src/trap.rs (segv_fixup_handler) only scans
whole registers for in-range values — it patched x1 (wrong register,
coincidentally in range) and crashed on retry.
**Fix direction (agreed):** decode the faulting instruction
(register-offset loads/stores), compute effective address from
Rn/Rm, and add base_offset to the register that makes
ea == fault_addr (prefer Rm when Rn looks like a valid host ptr).
TDD: pure helper taking (instr, regs, fault_addr, lo, hi, offset) →
Some(reg_to_fix). Use decoder::… GPR field tables if helpful.

### vim symlink issue (task #1, PENDING, easy)

`ubuntu-rootfs/usr/bin/vim` → `/etc/alternatives/vim` →
`/usr/bin/vim.basic` — absolute symlinks resolve against HOST /.
Loader should resolve symlinks inside FAKELINUX_ROOT (probably in
rootfs.rs or loader path open). vim.basic works directly.

## Other known issues (from session 6, still open)

- AF_UNIX sun_path not rootfs-translated.
- Guests appear to survive SIGTERM (only SIGKILL works).
- itimerval tv_usec: macOS i32 vs Linux i64 mismatch for nonzero usec.
- SA_SIGINFO unsupported (x1/x2=0 in handlers) — docs/known-issues.md.
- Stale /etc/*.lock in rootfs after SIGKILLed runs:
  `rm -f ubuntu-rootfs/etc/{group,gshadow,passwd,shadow}.lock`
- X30_BECAME_HEAP! diagnostics = noise (gcc uses x30 as scratch).

## Context-refresh protocol (taught by user this session)

When context gets ~90%: 1) save state into handoff.md + memory;
2) set a one-off heartbeat/reminder instructing to read handoff.md;
3) `tttt_self_inject` the `/clear` command. The heartbeat then picks
up and work continues. (This file you're reading IS that handoff.)

## Suggested order next

1. ~~vim initial-redraw~~ DONE (gettimeofday i32/i64 tv_usec, aaa62ce).
2. python3 lazy-reloc instruction decoder (TDD).
3. Symlink resolution through rootfs.
4. apt-get install python3 (it's apt — should work) + run python3.
5. Sweep for more macOS-i32-vs-Linux-i64 timeval bugs (getrusage).
