# Debug Task: Fork Child Runs Parent Code Path

## The Problem

In fakelinux (a Linux ABI emulator for macOS aarch64), when the apt-get gpgv
method forks a child to exec the real `gpgv` signature verification tool, the
**child process runs the parent's code path** instead of calling execve. This
causes apt-get update to hang after downloading InRelease files.

## How fakelinux works

fakelinux runs unmodified aarch64 Linux ELF binaries on macOS. The CPU IS
aarch64 — we emulate the Linux kernel ABI (syscalls, TLS, signals).

**Instruction interception**: Linux `SVC #0` instructions are patched to
`UDF #0xF000` at load time. The UDF triggers SIGILL, our handler reads the
syscall number from x8, dispatches to the emulation, writes the result to
x0 in the mcontext, advances PC by 4, and returns from the signal handler.

**Fork mechanism**: macOS can't fork() inside a signal handler. So fork is
deferred via a trampoline:

1. Guest calls `clone(SIGCHLD|..., 0, ...)` → SVC → UDF → SIGILL handler
2. Handler calls `do_fork()` which sets `FORK.mark_pending()` and returns
   sentinel `0xFFFF_FFFF_0000_F0C0`
3. `check_and_redirect()` (still in the handler) saves guest registers into
   `FORK.saved_regs`, sets x0 to the sentinel, and modifies the mcontext PC
   to point to the trampoline page
4. Signal handler returns → macOS sigreturn → execution jumps to trampoline
5. `fork_trampoline_entry()` runs (outside signal context):
   - Calls real `libc::fork()`
   - Child: `init_child_after_fork()`, then `FORK.set_x0(0)`,
     then `FORK.restore_and_resume()` → restores all guest regs, jumps to
     saved PC (instruction after the clone SVC)
   - Parent: `FORK.set_x0(child_vpid)`, then `FORK.restore_and_resume()`

Key files:
- `src/thread.rs`: `do_fork()`, `fork_trampoline_entry()`, lines ~398-448
- `src/trampoline.rs`: `Trampoline` struct, `check_and_redirect()`,
  `restore_all_regs()` (naked asm), `set_x0()`, `restore_and_resume()`
- `src/trap.rs`: `trap_handler()` (SIGILL handler), `init_child_after_fork()`
- `src/syscall.rs`: `do_clone_with_regs()` dispatches to `do_fork()`

## What we've verified

1. **x0 = 0 in child**: Traced `fork_trampoline_entry()` — the child always
   gets `return_pid=0` and calls `FORK.set_x0(0)` before `restore_and_resume()`.

2. **Instructions at resume PC are intact**: Dumped 8 instructions at the
   resume point. They match glibc's `__libc_fork` exactly:
   ```
   0xb140041f  CMN x0, #1, LSL #12    (error check: x0 > -4096?)
   0x54000188  B.HI error_handler      (branch if error)
   0x2a0003e2  MOV w2, w0              (save fork return to w2)
   0x350000e0  CBNZ w0, parent_label   (if w0≠0 goto parent)
   0xd11d00a6  SUB x6, x5, #0x740     (child: thread setup)
   0xd11980a0  SUB x0, x5, #0x660     (child: robust list addr)
   0xd2800301  MOVZ x1, #0x18         (child: robust list size)
   0xd2800c68  MOVZ x8, #0x63         (child: set_robust_list syscall)
   ```
   None of these were corrupted by our SVC/TPIDR/x18 instruction patcher.

3. **Child's observed behavior**: PID-annotated tracing shows the fork child
   immediately does `close(5)`, `write(6, config_data)`, `read(7, InRelease)` —
   this is the METHOD's processing code (parent path), not the exec path.

4. **The fork flags are normal**: `0x1200011` = CLONE_CHILD_SETTID |
   CLONE_CHILD_CLEARTID | SIGCHLD. Standard glibc fork().

5. **Pipe connectivity**: Parent's pipe read-ends (fds 5,6) are confirmed
   open and are valid pipes (lsof, fstat). The gpgv method's write(1) fails
   with EPIPE because nobody ever reads from the pipe.

## The mystery

glibc's child path after fork:
```
CMN x0, #1, LSL #12   → x0=0, no error
B.HI error             → not taken (correct)
MOV w2, w0             → w2 = 0 (saves fork return)
CBNZ w0, parent        → w0=0, NOT taken → falls through to child path
SUB x6, x5, #0x740    → child thread setup
SUB x0, x5, #0x660    → robust list address
MOVZ x1, #0x18        → size
MOVZ x8, #0x63        → syscall 99 = set_robust_list
SVC #0                 → (patched to UDF) → our handler → returns 0
MOV w0, w2             → w0 = 0 (restored from w2)
LDP x29, x30, [sp], #16
RET                    → returns to caller with w0=0
```

After RET, the caller (apt's method code) should check `pid == 0` and enter
the child exec path. But the child runs the parent processing path instead.

## What to investigate

1. **Is x5 correct?** The child path uses `x5` (thread pointer/pthread_self)
   for computing addresses. If x5 was clobbered by our signal handler or
   trampoline, the SUBs produce garbage addresses, and `set_robust_list`
   might write to a wrong location, possibly corrupting the stack or TLS.

2. **Does set_robust_list corrupt w2?** Our handler for syscall 99 returns 0
   in x0. We only modify x0 and PC in the mcontext. x2 should be preserved.
   But verify this — if the macOS SIGILL handler frame doesn't preserve x2
   across our trap handler invocation, w2 could be clobbered.

3. **Does restore_all_regs work correctly after fork?** The naked asm
   function uses the guest stack (sp from saved regs) to stash the branch
   target. After fork, the child has its own copy of the stack (COW). But
   the stash area (`sp - 32`) might conflict with data the child path uses.

4. **Is there a register clobbering issue in the trampoline?** The fork
   trampoline calls several Rust functions (pidns, init_child_after_fork)
   before restore_and_resume. If these functions use callee-saved registers
   that overlap with guest registers stored in SavedRegs, the compiler might
   clobber them.

5. **Check with a minimal test**: Write a test that forks inside fakelinux
   and verifies the child gets pid=0. Something like:
   ```c
   pid_t p = fork();
   if (p == 0) { write(1, "CHILD\n", 6); _exit(0); }
   else { write(1, "PARENT\n", 7); wait(NULL); }
   ```
   Compile for aarch64-linux, run under fakelinux.

## Build & test

```bash
cargo build
cargo test
bash tests/run_tests.sh  # 26 tests, all should pass

# Reproduce the hang:
timeout 30 env FAKELINUX_ROOT=./ubuntu-rootfs FAKELINUX_TRACE=1 \
  ./target/debug/fakelinux --container ./ubuntu-rootfs/usr/bin/apt-get update 2>&1 \
  | grep -E "do_fork|fork_trampoline|execve |FAILED"

# Test fork in bash:
timeout 5 env FAKELINUX_ROOT=./ubuntu-rootfs \
  ./target/debug/fakelinux ./ubuntu-rootfs/bin/bash -c 'echo $(echo hello)'
```

## Key code locations

- Fork trampoline entry: `src/thread.rs:407` (`fork_trampoline_entry`)
- Trampoline struct: `src/trampoline.rs:98` (`Trampoline`)
- restore_all_regs asm: `src/trampoline.rs:58`
- check_and_redirect: `src/trampoline.rs:207`
- save_regs: `src/trampoline.rs:139`
- set_x0: `src/trampoline.rs:173`
- Trap handler: `src/trap.rs:1070` (`trap_handler`)
- init_child_after_fork: `src/trap.rs:1251`
- Clone dispatch: `src/syscall.rs:180` and `src/thread.rs:173`
