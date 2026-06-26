# Session 2026-04-14 Continued: Deep Investigation of Fork LR Corruption

## Key Findings

### 1. The LR corruption is in x30 REGISTER at __libc_fork entry

Added FORK_ENTRY_PROBE at __libc_fork's first instruction (offset c1b50, `sub sp, sp, #0x140`). Found that x30 is ALREADY corrupted to a heap address (0x50000b728) when __libc_fork is entered. The `stp x29, x30, [sp, #224]` correctly saves this corrupted value.

**Proof**: Working forks show `lr_reg=0x10xxx77dc` (code), `fp_reg=SP` (ExecFork set fp=sp). Broken fork shows `lr_reg=0x50000b728` (heap), `fp_reg!=SP`.

### 2. ExecFork's saved LR is ALSO corrupted

ExecFork's saved return address at `[SP+8]` is 0x7ff07ffbd0 (a stack address, not code). This means the stack corruption affects multiple frames, not just __libc_fork.

### 3. The B instruction at libapt-pkg offset 0xB7EE4 is NOT corrupted

Initially suspected a false-positive x18 patch on a B instruction in libapt-pkg. Investigation proved the B instruction in libapt-pkg is NEVER corrupted. The UDF seen at "offset 0xB7EE4" is in libstdc++ (which has `MOV x0, x18` at the same relative offset in its own text segment). The libstdc++ patch is correct.

### 4. The corruption is broader than just return addresses

After fixing both __libc_fork's LR and ExecFork's caller LR via stack scanning, the gpgv method still crashes with SIGSEGV (NULL dereference). This suggests data pointers on the stack are also corrupted. The root cause is stack-level corruption in the gpgv method process.

### 5. The root cause remains unknown

The stack corruption affects the gpgv method (second-level fork process) but NOT apt-get (first-level fork). Both use the same ExecFork code path. The corruption happens during gpgv method execution, BEFORE it calls fork.

## Workaround Implemented

A FORK_ENTRY_PROBE at __libc_fork's entry:
1. Scans the stack for a value matching `libapt_base + 0xB77DC` (low 12 bits = 0x7DC)
2. If found, fixes x30 to this value (correct __libc_fork return address)
3. Also fixes ExecFork's saved caller LR at `[SP+8]` to `libapt_base + 0xB7CB8`

This fixes the fork child issue but the gpgv method parent still crashes due to broader stack corruption.

## Diagnostic Infrastructure Added

| Diagnostic | File | Purpose |
|---|---|---|
| FORK_ENTRY_PROBE | trap.rs, loader.rs | Intercepts __libc_fork entry, logs/fixes x30 |
| X30_LAST tracking | trap.rs | Tracks x30 across traps to detect heap transitions |
| LIBAPT_B_WATCH | trap.rs, loader.rs | Monitors libapt-pkg's B instruction for corruption |
| WRITE_X30 check | trap.rs | Logs any write_gpr to x30 (confirmed: never fires) |
| OFFSET_CHECK | loader.rs | Verifies instruction at offset 0xB7EE4 during patching |

## What Needs Investigation Next

### Most likely cause: Stack corruption from x18 emulation side effects

The emulated `MOV x0, x18` at libstdc++ offset 0xB7EE4 reads the guest's x18 value and puts it in x0. If x18 contains a pointer that later gets used incorrectly, it could corrupt the stack through intermediate operations.

### Investigation steps

1. **Check what x18 holds in the gpgv method**: Add logging when x18 emulation fires, showing the emulated x18 value and destination register.

2. **Track stack writes through x18**: If any emulated x18 instruction performs a STORE through x18 (using x18 as base register), log the target address. If it's on the stack, that's the corruption source.

3. **Compare stack state between apt-get and gpgv method**: The gpgv method has stack corruption but apt-get doesn't. What's different? The gpgv method loads additional libraries (crypto, etc.) that apt-get doesn't load in the same code path.

4. **Check if the corruption is from a heap-allocated buffer overflowing into the stack**: The corrupted values are heap addresses (0x5000xxxx). A heap buffer overflow could write heap pointers into stack memory if the heap and stack are close.

## Key Offsets

| Library | Offset | What |
|---|---|---|
| libapt-pkg | 0xB77C4 | ExecFork(set<int>) entry |
| libapt-pkg | 0xB77D8 | `bl fork@plt` (encoding 0x97FE0E22) |
| libapt-pkg | 0xB77DC | ExecFork return from fork@plt |
| libapt-pkg | 0xB7C10 | ExecFork(void) entry |
| libapt-pkg | 0xB7CB8 | ExecFork(void) return from ExecFork(set<int>) call |
| libapt-pkg | 0xB7EE4 | B instruction in ExecFork's code (NOT corrupted) |
| libapt-pkg | 0xB6E44 | MRS x19, tpidr_el0 (only TPIDR patch in libapt-pkg) |
| libstdc++ | 0xB7EE4 | `MOV x0, x18` (correctly patched as x18) |
| libc | 0xC1B50 | __libc_fork entry (`sub sp, sp, #0x140`) |
