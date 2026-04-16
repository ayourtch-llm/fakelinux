# Fork Concurrency Analysis

## Overview

This document describes the fork design in fakelinux and analyzes a critical data race that exists when two guest threads simultaneously execute `clone()` with `CLONE_VM=0` (process fork).

---

## The Fork Design

### High-Level Architecture

Fakelinux intercepts Linux syscalls by patching `SVC #0` instructions in the guest binary to `UDF #0xF000`. When the guest executes a syscall, macOS delivers SIGILL, which fakelinux catches in its signal handler, emulates the syscall, and returns the result.

**The problem**: `fork()` is unsafe to call from inside a signal handler on macOS. macOS's `fork()` runs `atfork` handlers that can close file descriptors, acquire mutexes, and perform other operations that are not async-signal-safe. If the signal handler itself has acquired locks or modified internal state, calling `fork()` can corrupt the child's state.

**The solution**: The **trampoline pattern** — defer the actual `fork()` call to a context outside the signal handler.

### The Trampoline Pattern

```
1. Signal handler marks a trampoline as pending
2. Signal handler redirects sigreturn PC to the trampoline page
3. Trampoline runs outside signal context, does the unsafe work
4. Trampoline restores guest registers and resumes guest execution
```

### Implementation Details

#### The Fork Flow

**Step 1 — Signal Context (`do_fork` in `src/thread.rs`):**

```rust
fn do_fork(flags: u64, child_tid_ptr: u64) -> u64 {
    FORK_FLAGS.store(flags, Ordering::SeqCst);
    FORK_CHILD_TID_PTR.store(child_tid_ptr, Ordering::SeqCst);
    FORK.mark_pending();
    0xFFFF_FFFF_0000_F0C0  // sentinel — trap handler intercepts
}
```

**Step 2 — Trap Handler (`check_and_redirect` in `src/trampoline.rs`):**

```rust
pub fn check_and_redirect(mctx, uctx, result, resume_pc) -> bool {
    for each registered trampoline:
        if t.pending.swap(false, Ordering::SeqCst) {
            t.save_regs(&mctx.ss, resume_pc);
            t.set_x0(result);
            mctx.ss.pc = t.addr();   // redirect sigreturn to trampoline page
            return true;
        }
    false
}
```

**Step 3 — Trampoline Entry (`fork_trampoline_entry` in `src/thread.rs`):**

```rust
extern "C" fn fork_trampoline_entry() -> ! {
    let flags = FORK_FLAGS.load(...);
    let child_tid_ptr = FORK_CHILD_TID_PTR.load(...);
    // ... save/restore CLOEXEC flags, stack canary, LR ...
    let pid = unsafe { libc::fork() };
    // ... handle child/parent ...
    FORK.restore_and_resume();  // never returns
}
```

### Shared State

The fork path uses **global shared state** — no per-thread isolation:

| Shared Variable | Location | Purpose |
|---|---|---|
| `FORK_FLAGS: AtomicU64` | `src/thread.rs:400` | Clone flags passed to fork |
| `FORK_CHILD_TID_PTR: AtomicU64` | `src/thread.rs:401` | Child TID pointer |
| `FORK: Trampoline` | `src/thread.rs:381` | Single trampoline instance |
| `FORK.pending: AtomicBool` | `src/trampoline.rs:127` | Pending flag |
| `FORK.regs: UnsafeCell<SavedRegs>` | `src/trampoline.rs:128` | Saved guest registers (29 regs + fp/lr/sp/pc) |
| `FORK.page_addr` | `src/trampoline.rs:126` | Single executable page address |

There is also a `PATCH` trampoline using the same pattern for `mprotect` + code patching, with the same concurrency issues.

---

## The Race Condition

### The Scenario: Two Threads Fork Simultaneously

```
Time  Thread A                                      Thread B
────  ────────────────────────────────────────────── ─────────────────────────────────────────────
T1    do_fork(flags=A, tid=A)
      FORK_FLAGS = A                                  (FORK_FLAGS = A)
      FORK_CHILD_TID_PTR = A                          (FORK_CHILD_TID_PTR = A)
      FORK.pending = true                             (pending = true)
      returns sentinel

T2    check_and_redirect(mctx_A)                      do_fork(flags=B, tid=B)
      pending.swap(false) → true                      FORK_FLAGS = B        ← OVERWRITES A!
      save_regs(&mctx_A.ss)                           FORK_CHILD_TID_PTR = B ← OVERWRITES A!
      set_x0(result_A)                                FORK.pending = true   ← re-sets after A cleared it
      mctx_A.pc = FORK.addr()

T3    check_and_redirect(mctx_B)                      [sigreturn fires]
      pending.swap(false) → true                      fork_trampoline_entry()
      save_regs(&mctx_B.ss)                           flags = FORK_FLAGS.load() = B
      set_x0(result_B)                                child_tid = FORK_CHILD_TID_PTR = B
      mctx_B.pc = FORK.addr()                         FORK.regs = Thread B's regs
                                                      calls libc::fork() with Thread B's args!

T4    [sigreturn fires]
      fork_trampoline_entry()
      reads FORK_FLAGS = B (or A — depends on timing)
      reads FORK.regs = Thread B's regs (or A)
      ALSO calls libc::fork() with wrong args!
```

### What Gets Corrupted

1. **`FORK_FLAGS` and `FORK_CHILD_TID_PTR`** — single global atomics. The second thread's store overwrites the first thread's values before the first thread's trampoline has read them.

2. **`Trampoline.regs`** — a single `UnsafeCell<SavedRegs>`. Thread B's `save_regs()` overwrites Thread A's saved register state.

3. **`pending` flag** — single `AtomicBool`. Thread B's `mark_pending()` after Thread A's `swap(false)` sets it to true again, but now both threads' trampolines are "pending" simultaneously.

4. **Single trampoline page** — both threads redirect sigreturn to the same address and execute the same code concurrently.

### Consequences

The most likely outcome: **Thread A's fork executes with Thread B's arguments**. The guest would see:

- Wrong clone flags (could cause thread creation instead of process fork, or vice versa)
- Wrong `child_tid_ptr` (could corrupt memory or fail to clear TID)
- Corrupted register state (sp, pc, etc.) — the guest resumes at the wrong address with wrong registers
- Both threads calling `fork()` concurrently, potentially creating more processes than expected

---

## Why the Race Is Hard to Hit

Several factors reduce the probability of manifestation:

1. **Most guests are single-threaded** — the common case (running `dash`, `apt`, etc.) involves single-threaded execution.

2. **Fork is rare** — even in multi-threaded programs, fork is typically called from a dedicated thread or after acquiring locks that the guest uses.

3. **Small race window** — the time between `mark_pending()` and trampoline execution is short (one sigreturn).

4. **macOS signal delivery serialization** — while not guaranteed, the OS may serialize signal delivery in practice under load.

5. **glibc's fork path** — most forks go through `__libc_fork`/`_Fork` which is called from a specific code path, reducing the chance of simultaneous entry.

---

## Signal Handler Concurrency

### Can Two Threads Be in the Trap Handler Simultaneously?

**Yes.** The SIGILL handler is installed with:

```rust
sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
libc::sigemptyset(&mut sa.sa_mask);  // sa_mask is EMPTY
```

An empty `sa_mask` means **SIGILL is NOT blocked during handler execution**. On macOS (POSIX), signals are delivered per-thread. If Thread A hits UDF, Thread A gets SIGILL. If Thread B hits UDF simultaneously on a different core, Thread B gets SIGILL. Both trap handlers run concurrently.

The `IN_TRAP` flag is set but **never checked** for serialization — it's only used by `signal_forwarder` to defer guest signal delivery.

---

## Same Pattern: PATCH Trampoline

The `PATCH` trampoline uses the identical design and has the same race:

```rust
pub static PATCH: Trampoline = Trampoline::new();
static mut PENDING_PATCH: Option<PendingPatchWork> = None;
```

Two threads calling `mprotect` + code patching simultaneously would race on `PENDING_PATCH` and `PATCH.regs`.

---

## Potential Fixes

### Option 1: Per-Thread Trampoline Pool

Replace the single `FORK` trampoline with a pool indexed by thread identity:

- Use the guest's TPIDR_EL0 (already tracked per-thread via pthread key) to select the right slot
- Each slot has its own `pending` flag, `SavedRegs`, and executable page
- `check_and_redirect` looks up the correct slot based on the current thread's TPIDR

```rust
const MAX_THREADS: usize = 64;
static FORK_POOL: [Trampoline; MAX_THREADS] = ...;
// In check_and_redirect:
let tpidr = get_thread_tpidr();
let slot = tpidr_to_slot(tpidr);
if FORK_POOL[slot].pending.swap(false) { ... }
```

### Option 2: Serialize at the Syscall Level

Acquire a global mutex before entering the fork path. This is simpler but introduces blocking in signal context, which is problematic — it would need to be done before the trap (e.g., by intercepting clone at a higher level).

### Option 3: Lock-Free Ring Buffer

Use a lock-free ring buffer for pending fork requests, with the trampoline draining one entry at a time. Each entry contains the full fork context (flags, tid_ptr, saved regs).

---

## Code References

| Component | File | Line(s) |
|---|---|---|
| Fork trampoline declaration | `src/thread.rs` | 381 |
| Fork flags storage | `src/thread.rs` | 400-401 |
| `do_fork()` signal context | `src/thread.rs` | 403-428 |
| `fork_trampoline_entry()` | `src/thread.rs` | 430-700 |
| Trampoline struct | `src/trampoline.rs` | 125-129 |
| `Trampoline::save_regs()` | `src/trampoline.rs` | 153-158 |
| `Trampoline::restore_and_resume()` | `src/trampoline.rs` | 183-205 |
| `check_and_redirect()` | `src/trampoline.rs` | 247-265 |
| Trampoline registry | `src/trampoline.rs` | 214-221 |
| PATCH trampoline | `src/thread.rs` | 385-392 |
| PATCH pending work | `src/thread.rs` | 707-708 |
| `patch_trampoline_entry()` | `src/thread.rs` | 720-735 |
| SIGILL handler install | `src/trap.rs` | 1919-1931 |
| `IN_TRAP` flag | `src/trap.rs` | 9 |
| Trap handler entry | `src/trap.rs` | 1394-1395 |
| clone syscall dispatch | `src/syscall.rs` | 192 |
| `do_clone_with_regs()` | `src/thread.rs` | 173-240 |