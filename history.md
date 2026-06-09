# fakelinux — session history / war stories

A running log of what got fixed, how it was found, and what the bug
actually was. Newest entries at the top. (Companion to `docs/diary.md`
and `handoff.md` — this one is the narrative for humans.)

## 2026-06-10 (session 7, part 3) — TLS works: two crypto-adjacent bugs

The road to `git clone https://gerrit.fd.io/r/vpp` went through TLS,
and TLS was broken in two completely different ways.

### Bug 1: trap_handler Rust panic on `ins v0.b[7], w18` (0b1192b)

python `ssl.wrap_socket()` aborted with exit 134 — a Rust panic
**inside the SIGILL trap handler** (panic in extern "C" = cannot unwind
= abort). The panic message said it all once captured with
RUST_BACKTRACE: `UNHANDLED EmulClass::Other for instr=0x4e0f1e40`.

Decoded: `ins v0.b[7], w18` — OpenSSL's AES asm inserting a byte from
**w18** into a SIMD register. The patcher correctly flagged it (reads
guest x18) but the emulator had no handler for the AdvSIMD copy class.
Wrote `emul_simd_copy`: DUP (element/general), INS (general/element),
SMOV, UMOV — vector forms included since the patcher also matches v18
in the Rn field. 6 new tests. Result: `print(t.version())` → TLSv1.3.

### Bug 2: nettle hashed garbage — K tables "patched" (the good one)

git still failed: `gnutls_handshake() failed: Decryption has failed`,
same for github — systemic. Bisect: every cipher failed, every group
failed, `GNUTLS_CPUID_OVERRIDE=0x1` (no accel) failed. Then the gold
nugget: `printf abc | nettle-hash -a sha256` returned **the wrong
hash**, identical for C and asm paths (`NETTLE_FAT_OVERRIDE`). And
sha1/md5 were *correct* — only sha256/sha512 wrong. What do those two
have that the others don't? **Big K constant tables in .rodata.**

(User, half-asleep, from memory: "we had this bug earlier — hash table
constants got accidentally 'relocated'." Exactly the right instinct.)

`FAKELINUX_NO_X18=1` made hashes correct → x18 false-positive patches
were corrupting the K tables. Root cause: libnettle has ONE R-X LOAD
covering .text *and* .rodata. At runtime ld.so doesn't map section
headers (end of file), so `patch_new_code`'s eh_frame strategy found
nothing and fell back to "whole exec segment" — including .rodata,
where K constants decode like x18-touching instructions.

Fix (TDD, new test truncates libnettle at the LOAD boundary to simulate
the runtime view): implement the long-TODO'd Strategy 2 — locate
.eh_frame via **PT_GNU_EH_FRAME** (.eh_frame_hdr IS mapped), decode the
`eh_frame_ptr`, hand off to the existing FDE parser. Memory-view ranges
now byte-identical to file-view ranges.

After: nettle hashes correct, `gnutls-cli stdio.be:443` (user's server)
handshake completed, and **git clone over https works**. 348 tests.

### Side notes

- Enabled `universe` in the container's apt sources (gnutls-bin,
  nettle-bin live there) — handy for future debugging.
- Remaining ungated debug spam during git/fork: POST_FORK_LR, ASM_X0,
  STACK_DUMP `[sp+..]`, X30_BECAME_HEAP — still to gate like 49cee40.

## 2026-06-09 (session 7, part 2) — vim redraw + python3 ET_EXEC

### python3.12 runs! (f7319ff)

Ubuntu builds python3.12 as **non-PIE** (ET_EXEC, load address
0x400000). macOS forbids mapping below 4GB (PAGEZERO), so fakelinux
relocates the image to 0x700000000 and then has to find every absolute
pointer baked into the binary. Three-act story:

1. **Act 1 — the wrong register.** python crashed in a libc strcpy
   loop: `LDR x3, [x0, x10]` faulting on unrelocated `0x701f60`. But
   x0 was a perfectly valid host stack pointer and x10 a huge "negative"
   value — only their *wrapped sum* was the unrelocated address. The old
   fixup scanned all registers for in-range values and patched innocent
   x1. **Fix:** decode the faulting instruction (reg-offset, immediate,
   pre/post-index, LDP/STP, SIMD LD1/ST1), compute the effective
   address, and fix the register actually involved. TDD: 10 unit tests
   from real crash encodings.

2. **Act 2 — the 28GB malloc.** python then looped forever calling
   `mmap(len=0x700001000)` — 28GB! — until the kernel SIGKILLed it.
   `0x700001000 = relocation_offset + 0x1000`: someone computed
   `relocated_ptr - unrelocated_ptr` as a size. New diagnostic: on
   huge mmaps, walk the guest frame-pointer chain (fault-safe Mach
   reads) and print a backtrace. Resolved symbols via .dynsym:
   `Py_InitializeFromConfig → PyUnicode_FromString →
   _PyUnicodeWriter_Finish → PyObject_Realloc`. Root cause: the
   loader's pointer-fixup scan only covered **writable** segments, but
   non-PIE binaries keep const pointer tables in **.rodata** —
   python3.12 has **6,094** of them. **Fix:** scan .rodata too
   (mprotect RW, patch, restore).

3. **Act 3 — self-inflicted SIGBUS.** First version of the .rodata fix
   restored edge pages to PROT_READ — but a 16KB page at the section
   boundary was *shared with .text*, which lost PROT_EXEC → SIGBUS on
   instruction fetch. **Fix:** restore each page's protection from the
   covering PT_LOAD flags.

Result: `python3.12 -c 'import sys, hashlib; ...'` works, exit 0.

### vim fully works (aaa62ce)

Symptoms: blank screen at startup until entering insert mode;
insert-mode typing invisible until ESC; Ctrl-C "not working".

The decisive trace observation: vim **read** keystrokes but issued
**zero write(1)** calls — it was choosing not to draw, waiting for a
deadline that never expired (pselect timeouts of 545,460 *seconds* in
the trace).

Root cause: syscall 169 (gettimeofday) was passed straight to macOS.
macOS `timeval.tv_usec` is **i32** (writes 12 bytes); Linux aarch64
expects **i64** (16 bytes) — the high 4 bytes of tv_usec kept stale
stack garbage, wrecking vim's termresponse deadline arithmetic. One
two-line conversion fixed all three symptoms.

**Bug class to remember:** macOS `suseconds_t` is i32. Anything
passing `struct timeval`/`itimerval`/`rusage` pointers through
unconverted has this bug (getrusage still unswept).

### Also

- Fork-child debug spam (FORK_TRAP/CHILD_SVC/wait4 lines flooding
  apt-get output) gated behind FAKELINUX_TRACE (49cee40).
- ../mcp-pty-server: `[ESC]` accepted as alias for `[ESCAPE]` (247e02b).
- Discovered: the "apt-get install git never finishes" report was
  python3.12-minimal's postinst invoking the (then-broken) python —
  same root cause as the python3 work above.

## Earlier sessions

See `docs/diary.md` for sessions 1–6 (UMULH/MADD zstd corruption,
nested-fork SIGCHLD race, XZ thread deadlock, x18 trampolines,
.eh_frame literal-pool parsing, apt-get networking, mprotect rounding,
rt_sigtimedwait + POSIX timers, …).
