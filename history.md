# fakelinux — session history / war stories

A running log of what got fixed, how it was found, and what the bug
actually was. Newest entries at the top. (Companion to `docs/diary.md`
and `handoff.md` — this one is the narrative for humans.)

## 2026-06-10 (session 7, part 5) — install-dep at 99%: garbage in x3 and a leaky TMPDIR

The big `make install-dep` run finished with DONE_RC=2: 276 of 279
packages in, three out — man-db plus two perl libs. Two more bugs, both
again of the "macOS is not Linux" family rather than emulation:

1. **fchmodat has no flags argument.** man-db's unpack died with
   `unable to install new version of './var/cache/man': Permission
   denied`. The trace showed the real failure was `renameat(...) →
   EACCES` renaming `man.dpkg-new` → `man`. Why? dpkg creates dirs as
   `mkdir(path, 0000)` then `chmod(0755)` — and our chmod never landed.
   Linux `fchmodat` (syscall 53) takes only `(dirfd, path, mode)`;
   flags exist only in `fchmodat2` (452). We were forwarding **x3 —
   call-site garbage** (0xc from dpkg) — as flags to macOS fchmodat,
   which returned EINVAL… and the virtual-root "fake success on EPERM"
   fallback swallowed it. So the dir stayed mode 000 and macOS refused
   to rename a search-denied directory. One-line fix + a regression
   test that passes garbage x3 and asserts the chmod really lands.

2. **Host TMPDIR leaked into the container.** After the fix,
   `dpkg --configure -a` still failed in dictionaries-common:
   ispell-autobuildhash ran `mktemp -d` under
   `/var/folders/nm/…/T/` — macOS's per-user temp dir, straight from
   the host environment, nonexistent in the rootfs. `build_guest_env`
   now strips `TMPDIR`, `__CF_USER_TEXT_ENCODING`, and `XPC_*`.

The two perl debs ("does not look like a tar archive" from
`dpkg-deb --control`) refused to reproduce — 5× clean in isolation,
sequential and parallel. Filed as "transient under load, watch the
rerun". Bonus terminal archaeology: bash decides interactivity by
`isatty(stderr)` **at startup**, so redirecting the container's stderr
to a log file silently killed the prompt; the fix is
`bash -c 'exec /bin/bash -i 2>&1'` so the guest's stderr returns to
the pty while fakelinux's own host-side spam stays in the log.

`dpkg --configure -a` then ran clean (FIX_RC=0) and install-dep is
rerunning. 360 tests green (the libcrypto eh_frame test also needed
its hardcoded offsets refreshed — apt had upgraded the rootfs's
libcrypto.so.3 out from under it; it now finds the SHA-256 K table by
content).

## 2026-06-10 (session 7, part 4) — the road to `make build`: two host-OS impedance mismatches

vpp is cloned (`git fsck` exit 0) and `make` inside the container
prints the full VPP target menu. Getting `make install-dep` to run
surfaced two delicious "macOS is not Linux" bugs that had nothing to
do with instruction emulation:

1. **Case-insensitive APFS vs linux-libc-dev.** `apt-get install
   build-essential` died unpacking kernel headers:
   `unable to install new version of '/usr/include/linux/netfilter/
   xt_connmark.h': No such file or directory`. The netfilter headers
   ship **eight case-colliding pairs** (`xt_connmark.h` vs
   `xt_CONNMARK.h`, `ipt_ecn.h` vs `ipt_ECN.h`, …iptables match vs
   target convention). On case-insensitive APFS both `.dpkg-new`
   temp files are the *same file*; the first rename consumes it and
   the second rename gets ENOENT. Fix (pragmatic): a dpkg
   `path-exclude` conffile in the rootfs dropping the 8 uppercase
   variants (VPP's source references none of them). The *real* fix
   would be a case-sensitive APFS volume for the rootfs.

2. **sudo vs host file ownership.** VPP's Makefile shells out to
   `sudo`, and freshly-installed sudo refused:
   `/etc/sudoers is owned by uid 501, should be 0`. We virtualize
   credentials (guest is uid 0, unshare -r style) but stat results
   leaked raw host uids. Fix: `creds::map_host_id` — our host uid/gid
   maps to 0, everything else to 65534 (Linux overflowuid), wired into
   both stat translators (6788b41). `sudo true` now works in-container.

Also: TaskList + handoff survived context refresh #4; build-essential
(gcc 13, g++, make, dpkg-dev) installed clean once the collision was
excluded.

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

## Session 7, refresh #5 (2026-06-10)

**py3compile pipe deadlock SOLVED** (afd5a6a). The 6-hour install-dep hang
turned out to be a beautiful one: lsof on the two stuck processes showed a
pipe pair (parent fd 5 ↔ child fd 6) that had no business existing — it was
CPython subprocess's *errpipe*, created with O_CLOEXEC, which should have
died when the child exec'd py_compile. fakelinux strips FD_CLOEXEC from all
fds before macOS fork (atfork handlers would close them otherwise) and
restores it only in the parent — the exec'd child kept the errpipe open, so
Popen() in the parent waited forever for EOF on it, and the child waited
forever for stdin that the parent (stuck inside Popen!) never wrote. Fix:
re-apply saved CLOEXEC bits right before execve, and forget bits when the
child closes/dup2s over an fd. TDD: 2 mask-lifecycle unit tests (356 green),
then the live repro: `Popen(['python3.12','-m','py_compile','-'], bufsize=0,
stdin=PIPE)` → rc 0 in seconds instead of hanging.

**Then sudo hung too** — and this one was a double-decker (4436232). After
apt-get update finished, sudo sat in ppoll() with a zombie child, forever.
sudo blocks SIGCHLD and counts on ppoll to atomically swap in a mask that
unblocks it — fakelinux ignored ppoll's sigmask argument entirely. Fixing
that wasn't enough: the wait STILL hung, because do_ppoll executes inside
the SIGILL trap handler, whose sa_mask (the very fix for the nested-fork
race!) blocks every host signal — so a SIGCHLD arriving mid-wait couldn't
even run the forwarder to be queued as pending. Final shape: swap
GUEST_SIGMASK for the wait, poll in 100 ms chunks with host signals
unblocked, EINTR when a pending signal with a real handler becomes
deliverable, and a TIF_RESTORE_SIGMASK-style override so the handler's
sigreturn restores the pre-ppoll mask. Plus `Defaults !use_pty` in
sudoers (we have no /dev/ptmx). sudo /bin/echo: instant. 358 tests green.
install-dep is rerunning now.

## Session 7, refresh #9→#10 (2026-06-10, ~10:00)

**install-ext-deps attempt #1: died at the dpdk extract** — and the
culprit was a syscall I'd never heard of until today: **fchmodat2
(452)**, Linux 6.6's "fchmodat but with the flags argument it always
should have had". Modern GNU tar calls it with AT_SYMLINK_NOFOLLOW for
every extracted file. fakelinux said ENOSYS, tar fell back to a
symlink-following chmod, and the dpdk tarball's doc symlinks
(doc/api/dts/custom.css → ELOOP "Too many levels of symbolic links")
made tar exit 2. Implemented it properly (2206b8b): translate Linux
AT_SYMLINK_NOFOLLOW 0x100 → macOS 0x20, resolve the path *without*
following the final symlink, TDD with a symlink-mode test proving we
chmod the link and not the target. 364 tests green.

Bonus finding from the same log: a storm of write(1)=EAGAIN on a pipe
from one pid — but F_SETFL flags ARE translated, so that's a guest that
*asked* for nonblocking stdout and poll-loops on it. Noise, not a bug
(daq built fine through it). The diagnostic eprintln is on the
FAKELINUX_QUIET shortlist though.

daq's stamps all survived (.daq.*.ok), so the rerun resumes straight at
the dpdk extract. Container relaunched on the fresh binary; ext-deps
running again with monitors on the done-marker and a 15-min stall
detector. Expect hours: dpdk + rdma-core + xdp-tools under emulated
clang.

## Session 7: the hello-world that broke gcc (2026-06-10, ~11:00)

User side quest: `gcc test.c` — five lines of hello world — ICE'd cc1
with "internal compiler error: Segmentation fault". The trail was a
beauty. cc1 is ET_EXEC, so we relocate it to 0x700400000 and our
heuristic scans .rodata for "things that look like unrelocated
pointers" to fix up. A switch jump table — an array of little 16-bit
code offsets — had four consecutive halfwords [0x0000, 0x0054, 0x0000,
0x0000]. Read as a u64 that's 0x540000: smack in the pointer range.
The fixup added 0x700000000, which wrote 0x0007 into what was a 0x0000
table entry. Tree code 28's switch case then `br`'d into the middle of
an unrelated basic block in equiv_oracle::find_equiv_block, loaded a
garbage "string pointer", and gcc's own SIGSEGV handler dressed our
bug up as an ICE.

User asked the right question: "is there a generic way that's less
fragile?" First answer — kill relocation entirely by shrinking
fakelinux's own __PAGEZERO (the Wine trick) so guests map at their
real 0x400000. macOS arm64 SIGKILLs small-pagezero binaries. Dead end.

Second answer, the one that stuck: stop guessing from data shape, read
the code. Pointer arrays load with `ldr x, [base, idx, lsl #3]`; jump
tables with `ldrh w, [base, idx, uxtw #1]` feeding add+br; and the
table's exact length is in the guarding `cmp` on the index register.
Three iterations, each correcting a real failure: (1) exclude only
true dispatch tables — over-excluding plain byte tables orphaned the
pointer data right after them; (2) bound from the cmp ON THE INDEX
REGISTER — the nearest-any-cmp grabbed a wrong compare, 5256-byte
exclusion, swallowed real pointers, driver strlen crash; (3) the lazy
SEGV fixup was silently DEAD in any process that installs its own
SIGSEGV handler (the forwarder had replaced it) — now the forwarder
tries the fixup before forwarding. gcc compiles and runs hello world
and -O2 fib; python3.12 regression intact; 371 tests green (0e44c32).

Meanwhile the fchmodat2 fix proved itself: dpdk extract passed, daq
built and installed, ext-deps grinding on.

## Session 7: top, and the ext-deps whack-a-mole (2026-06-10, ~12:00)

**top works now** — and the bug was a lovely one: /proc/stat was an
all-zeros stub, but even after feeding it real host CPU ticks
(host_processor_info — your Mac's actual per-core numbers), top kept
dying with ERANGE. The trail led into libproc2's source: it keeps
/proc/stat OPEN and re-reads it with fflush+rewind+fread on every
refresh. Our virtual /proc files were one-shot pipes — drained after
the priming read, so the reap got an empty buffer. Virtual files are
now tracked fds where lseek(0) REGENERATES the content — which is
exactly what real procfs gives you, and it makes the %CPU deltas
genuinely live (a 'yes' loop shows 100.0). /proc also lists every
guest process with real names (parsed out of KERN_PROCARGS2), real
utime/stime from proc_pid_rusage, real RSS. htop next, anyone?

**ext-deps attempt #2 still failed**, two new moles to whack:
1. clang compiling rdma-core hit `ld2 {v0.2d, v1.2d}, [x18]` — an
   AdvSIMD structure load through the forbidden register, which fell
   into the UNHANDLED-EmulClass panic. But it never needed emulating:
   only its base register is a GPR, so the x18→x17 trampoline handles
   it fine once told that "Other" class is safe for this family. Plus
   rt_sigpending(136) so ninja stops whining.
2. dpdk's meson venv: Debian's ensurepip said "disabled for the system
   python" INSIDE a venv. Root cause was deliciously indirect: our
   execve re-exec replaced guest argv[0] with the resolved binary path,
   so the venv's bin/python3.12 symlink became /usr/bin/python3.12,
   CPython never found pyvenv.cfg next to argv[0], and concluded it was
   the system interpreter. FAKELINUX_ARGV0 now carries the original
   argv[0] across exec. pip-24.0 installs clean.

And a regression caught by its own victim: the gcc jump-table exclusion
had a 4 KiB fallback for "dispatches" with no bounds-check cmp — which
matched CPython's frozen bytecode (ldrb opcode fetch + computed-goto
br) and left 417 real pointers unrelocated → ensurepip OOM-SIGKILL.
Real switch tables always have a guard cmp; no cmp now means no
exclusion. The determinism principle keeps winning.

Attempt #3 running: daq → rdma-core → dpdk, hours on the clock.

## The five-second curl (2026-06-10, while daq configures)

While attempt #3 ground through daq's configure, the user noticed
`curl stdio.be` took ages under fakelinux. Timing breakdown said it
all: DNS 0.09s, connect 0.13s, first byte 5.17s — a flat, deterministic
5 seconds, IPv4 or IPv6, even against a localhost python server. The
killer experiment: timestamp when the *server* receives the request.
sendto() returned 71 bytes instantly; the GET arrived server-side five
seconds later. The data sat in the kernel's send buffer.

The smoking gun was in the trace: curl enables TCP keepalive with
setsockopt(IPPROTO_TCP, TCP_KEEPIDLE=4, 60). Our sockopt translation
covered SOL_SOCKET but passed IPPROTO_TCP optnames through raw — and
on macOS, (IPPROTO_TCP, 4) is TCP_NOPUSH. We were corking every socket
curl opened, and macOS's infamous NOPUSH behavior holds the data ~5s.
A one-value namespace collision, invisible because setsockopt happily
returned 0.

Fix (d68fd35): proper TCP optname table (KEEPIDLE→TCP_KEEPALIVE,
CORK→NOPUSH, KEEPINTVL/KEEPCNT to their 0x10x values), and unknown TCP
optnames now return ENOPROTOOPT instead of passing through — colliding
value spaces mean pass-through is never safe. curl: 5.2s → 0.15s.
HTTPS still takes ~3s, but that's honest work: 95% CPU in the SIGILL
storm while emulated openssl does its handshake. Known issue, x18
trampoline coverage, another day.

## The staircase (2026-06-10, same afternoon)

Second user report: apt-get output loses its carriage returns mid-
install — classic terminal staircase — and the host terminal needs a
`reset` afterwards. Reproduced in a scratch pty on the first try: the
stairs start exactly at "(Reading database ...)" — the moment apt hands
off to dpkg.

The mechanism is elegant once you see it. apt's StartPtyMagic puts the
REAL terminal into raw mode (OPOST off) on purpose, and runs dpkg on a
pty slave carrying a copy of the original termios — the slave's ONLCR
is what turns dpkg's LF into CRLF. New TCSETS tracing showed our side
of the deal collapsing: tcsetattr on the pty MASTER returned -1. Linux
lets you drive the slave's line discipline through the master; macOS
says ENOTTY. And underneath that, a second bug: our TIOCSPTLCK
(unlockpt) was a polite no-op, so the macOS slave was never actually
unlocked — even apt's TIOCSWINSZ-on-master fallback path died with
EACCES trying to open it.

Fix (1dad433): unlockpt now really runs grantpt+unlockpt, and the
termios/winsize ioctls retry on a transiently-opened slave when the fd
turns out to be a master. apt output now comes down in straight
columns and the terminal survives. Bonus discovery: with the pty
actually working, dpkg children's stderr now lands on screen — the
FAKELINUX_QUIET idea moves up the wishlist.
