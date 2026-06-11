# Handoff — start here next session

_Last update: 2026-06-12 ~01:00 (session 9, refresh #15). Narrative in `history.md` (keep appending for the user!), full story in `docs/diary.md`._

## REFRESH #15 STATUS — read this first (supersedes #14 below)

**cc1 ICE FIXED (fcf612a) — root cause was OURS, found + TDD'd + committed:**
- insn_operand_data flags word for match_operator operands = u64
  `0x1000000|mode` (is_operator=1, eliminable=0) — inside cc1's ET_EXEC
  [0x400000,0x2400000) range. Eager pointer fixup added 0x7_0000_0000 →
  the +7<<32 landed EXACTLY in the `eliminable` byte → reload's
  elimination_costs_in_insn walked ccmp's match_operator AFTER zeroing
  its nested CC-reg slot (*recog_data.operand_loc[i]=0, reload1.cc) →
  eliminate_regs_1(NULL) → "during RTL pass: ira" ICE. genoutput.cc
  documents eliminable==0 for MATCH_OPERATORs — that 0 is the guard.
- Fix: loader.rs plausible_unrelocated_pointer() — reject sparse words
  (≤2 nonzero bytes) ≥16M with zero 0xFF0000 byte. First attempt
  (plain ≤2-bytes rule) broke python3.12 (sub-16M images have REAL
  sparse pointers — "__delattr__" string bytes chased as ptr); final
  rule keeps those. Verified: cc1 min2.i -O3 clean, python3 ssl OK,
  gcc -O3 compile+run OK, 387 tests green.
- **NEW DEBUG TOOL (7e933bb): FAKELINUX_WATCH=<seq>:<len>:<off>** (hex)
  in-process software watchpoint. Heap addrs vary run-to-run but anon
  mmap SEQUENCE is deterministic → name a slot as (k-th anon mmap of
  len L, offset O). PROT_READ page; on write fault patch pc+4 with UDF
  0xF00D, store executes natively, probe re-protects + logs old→new +
  writer pc/instr/regs. Found the cc1 writer in 2 runs (~40s each)
  after lldb conditional-bp proved useless (hours, perturbs layout).
  Crash dumps now also print [sp..sp+0xa0] (recovered the rtx ptr from
  the callee's spill at [sp+0x20] — no debugger needed).
- lldb lessons recorded: conditional bp on hot fn = ~30x slowdown via
  round-trips; expression evals allocate in inferior → CHANGES mmap
  layout; ignored-exceptions recipe still in #14 below if ever needed.

**IN FLIGHT: ext-deps resume + FULL VPP BUILD, detached (host PID 81402):**
- Script: ubuntu-rootfs/tmp/resume-ext5.sh — dpkg-buildpackage -b -nc
  (stamps intact, only xdp-tools rebuilds with WORKING gcc) → PKG_RC=
  → make -C build/external install-deb → INSTALLDEB_RC= → make build
  (UNATTENDED=y DEBIAN_FRONTEND=noninteractive PKG_VERSION=26.10
  PKG_SUFFIX=0) → DONE_RC=. Log: ubuntu-rootfs/tmp/ext5b.log.
- Monitor bm68eh8lx watches RC markers + ICE/panic/SIGSEGV sigs
  (dedup via /tmp/ext5b.seen). On DONE_RC=0: make run + PUSH NOTIFY
  user. If vpp's cmake build hits new emulation bugs, the
  FAKELINUX_WATCH tool + [sp..] dumps are the weapons.
- NOTE: binary now at fix commit; build started ~00:55.

## REFRESH #14 STATUS (older, lldb recipe still useful)

**ext-deps attempt #5: DONE_RC=2 — died at the LAST package (xdp-tools).**
Everything else BUILT+INSTALLED with stamps intact in
`ubuntu-rootfs/root/vpp/build/external/deb/_build/`: daq, rdma-core
(17:14, incl. 3h sanitize_static_lib llvm-nm/objcopy grind — that step
writes only to guest /tmp, looks like a stall but isn't), dpdk 26.03
(ALL 2002 ninja targets + install 22:31; meson venv pip worked —
c3a8f72 shebang-argv0 fix CONFIRMED in real build), quicly (22:35).

**CURRENT BUG — gcc-13 cc1 deterministic SIGSEGV (ICE) — IN PROGRESS:**
- xdp-tools is the only gcc user (everything else clang). cc1 ICEs on
  the FIRST real compile: libbpf bpf.c, -O3, "during RTL pass: ira".
  gcc driver's "bug is not reproducible" is a LIE — 100% deterministic.
- MINIMIZED REPRO (fast, ~30s):
  `FAKELINUX_ROOT=$PWD/ubuntu-rootfs ./target/release/fakelinux
  ubuntu-rootfs/usr/libexec/gcc/aarch64-linux-gnu/13/cc1 -fpreprocessed
  /tmp/min2.i -quiet -mlittle-endian -mabi=lp64 -O3 -fPIC -o /tmp/min2.s`
  (/tmp/min2.i = head -14093 of bpf.i, lives in ubuntu-rootfs/tmp/).
- Crash: pc=0x70100fadc `ldrh w20,[x19]` x19=0 (callee 0x100faa0 — an
  rtx-code switch helper — entered with x0=NULL). Caller callsite
  0x100fe04, loads arg from `ldr x0,[x19,#8]`.
- lldb session DATA (bp 0x70100faa0 cond $x0==0 HIT): caller x19 =
  heap rtx at 0x11970d780: [+0]=0x20000056 (rtx code 0x56=86, check
  which code that is in gcc-13 aarch64 rtl.def order!), [+8]=NULL ←the
  bug, [+16]=0x117dbd490 valid heap ptr, [+24]=0x20020034 (inline rtx
  header? code 0x34=52). Heap addrs NOT stable across runs — same-run
  watchpoint needed, or break earlier at rtx creation.
- -fdump-rtl-all: ira dump (301r.ira) for bpf_prog_load is COMPLETE
  (564 insns, sane RTL, no (nil) operands in wrong places); 302r.reload
  does NOT contain bpf_prog_load → corruption manifests between ira's
  RTL dump and reload (i.e. inside IRA allocation / start of LRA).
  Dumps: ubuntu-rootfs/tmp/min2dump.*.
- **LLDB-ON-GUEST RECIPE (works, hard-won!):**
  `settings set platform.plugin.darwin.ignored-exceptions
  EXC_BAD_INSTRUCTION|EXC_BAD_ACCESS` (BEFORE run; if launch says
  "attach failed" just retry — flaky once), `run` stops at first guest
  SIGILL (= anchor; guest text already mapped+patched), then
  `process handle SIGILL/SIGSEGV/SIGBUS/SIGCHLD --pass true --stop
  false --notify false`, then `breakpoint set -a 0x70100faa0 -c "$x0
  == 0"` + breakpoint command add, then continues. Script:
  /tmp/lldb-cc1c.txt (host /tmp). Without ignored-exceptions lldb
  stops on every Mach exception and lazy-reloc faults LOOP FOREVER.
- Suspects (unconfirmed): (a) ET_EXEC pointer fixup false pos/neg —
  loader.rs fixup_exec_pointers_skip_dynamic + scan_rodata_table_
  exclusions; cc1's global at 0x1ed8290 (adrp'd in callee) worth
  checking; (b) emulated-instruction bug à la UMULH (x18-fallback or
  SIMD path) corrupting IRA's bitmaps/pointers.
- Next debug steps: (1) identify rtx code 86 + the callee fn (objdump
  around 0x100faa0; compare gcc-13.2 aarch64 sources); (2) same-run
  watchpoint: bp where the rtx is allocated, watch [rtx+8]; cheaper:
  bp at 0x100fe04 (callsite) cond `*(long*)($x19+8)==0` to catch
  earlier visits; (3) FAKELINUX_TRACE_X18 audit of cc1 run, diff
  emulated-instr classes vs known-good; (4) try -O2 / -fno-* flag
  bisect to shrink which optimization triggers it.

**AFTER cc1 FIX — resume ext-deps WITHOUT the 12h clean rebuild:**
container: `cd /root/vpp/build/external/deb && dpkg-buildpackage -b
-uc -us -nc` (-nc = no clean → stamps survive, ONLY xdp-tools
rebuilds). Then back at top level the make stamps/deb install may need
`make -C /root/vpp/build/external install-deb` rerun (it'll find the
deb). THEN: `make build` (UNATTENDED=y DEBIAN_FRONTEND=noninteractive
PKG_VERSION=26.10 PKG_SUFFIX=0) + push notification to user.
NOTE: vpp `make build` may default to gcc → cc1 bug blocks it anyway;
fixing cc1 is NOT optional. Detach long builds with nohup + DONE_RC
log marker (usage outages kill harness wakeups; log = ground truth).
Monitor recipe: watch DONE marker + panic/Error sigs (dedup vs $seen)
+ true-stall = no file mtime in logs AND guest /tmp AND all fakelinux
procs <20% CPU (sanitize-type steps write only to /tmp scratch).

## REFRESH #13 STATUS (older)

**Two fakelinux bugs found by ext-deps attempts #3/#4, both fixed+committed on `testing`:**
1. **Shebang argv[0] symlink-resolved (c3a8f72)**: execve shebang branch
   removed FAKELINUX_ARGV0, so the interpreter saw the rootfs-resolved
   path (/tmp/venv/bin/python3 → /usr/bin/python3.12). CPython missed
   pyvenv.cfg → system prefix → PEP 668 "externally-managed-environment"
   killed dpdk's meson-venv pip install. Linux passes the shebang text
   VERBATIM as argv[0]; we now set FAKELINUX_ARGV0=interp
   (syscall.rs ~line 1898). Test: `tests/test_shebang_argv0.sh` (red→green).
2. **Env-lock self-deadlock in trap_handler (bf94855)**: handler called
   std::env::var (FAKELINUX_TRACE_LR/_X18 + lazy _X18_STORES). Signal
   landed while the forked child held the env lock in
   pidns::set_child_env setenv → handler blocked forever in
   env_read_lock (semaphore_wait_trap). Symptom: xdp-tools `sh configure`
   hung 10h, dash with 2 unreaped zombies; `sample <pid>` gave the stack.
   Fix: init_trace_flags() caches knobs in install_handler(); handler
   loads atomics only. Unit test trap::trace_flag_tests pins it.
   **RULE: nothing reachable from signal context may call std::env or
   any lock-taking std API.**

**ext-deps attempt #5 IN FLIGHT — DETACHED from Claude session:**
- nohup, host PID 37329 (whole tree survives /clear AND usage outages —
  attempt #4's 10h hang went unnoticed partly because usage ran out and
  scheduled wakeups couldn't fire; log markers are the source of truth).
- Log: `ubuntu-rootfs/tmp/ext-deps5.log`; completion marker line
  `DONE_RC=<n>` appended at end. No harness monitor survives /clear;
  NEXT SESSION: check `grep DONE_RC ubuntu-rootfs/tmp/ext-deps5.log`,
  re-arm a Monitor (dedup errors vs $seen var! and stall-check mtime of
  _build/*.log sub-logs — main log goes quiet during configure/ninja).
- Attempt #4 proved the whole chain works: daq, rdma-core (513 tgts),
  **DPDK 26.03 (meson venv pip OK, 2002 ninja targets, installed)**,
  quicly all built; only xdp-tools was left when it hit deadlock (2).
  dh clean wipes _build on every rerun → ~12h full rebuild per attempt.
- After DONE_RC=0: `make build` (UNATTENDED=y DEBIAN_FRONTEND=
  noninteractive PKG_VERSION=26.10 PKG_SUFFIX=0), then make run.
- Launch incantation (from repo root):
  `FAKELINUX_ROOT=$PWD/ubuntu-rootfs ./target/release/fakelinux
  --container ubuntu-rootfs/usr/bin/bash -c 'cd /root/vpp && make
  install-ext-deps > /tmp/ext-deps5.log 2>&1; echo "DONE_RC=$?" >>
  /tmp/ext-deps5.log'`
- Loose thread (minor): 36x `write(1) EAGAIN` pipe retry spam from one
  short-lived proc in attempt #4 — benign, but fakelinux's nonblocking
  pipe write path may deserve a retry/poll loop someday.

## REFRESH #12 STATUS (older)

**Two user-reported bugs FIXED + committed this refresh:**
1. **curl 5s delay (d68fd35)**: curl sets Linux TCP_KEEPIDLE
   (IPPROTO_TCP, optname 4); we passed TCP optnames through raw and
   macOS (6,4) is TCP_NOPUSH → socket corked → HTTP request sat ~5s in
   the send buffer. translate_sockopt now maps TCP_NODELAY/MAXSEG/
   CORK→NOPUSH/KEEPIDLE→TCP_KEEPALIVE/KEEPINTVL/KEEPCNT; unknown TCP
   optnames → ENOPROTOOPT (NEVER pass through — value spaces collide).
   curl stdio.be 5.2s→0.15s. (https still ~3.3s = honest CPU in SIGILL
   storm during TLS handshake — known x18-coverage perf item, NOT a bug.)
2. **apt-get staircase output + broken terminal (1dad433)**: apt's
   StartPtyMagic sets the REAL tty raw and pushes saved termios (ONLCR)
   onto dpkg's pty via the MASTER fd. Two bugs: (a) our TIOCSPTLCK
   unlock was a no-op → macOS slave stayed locked → slave open EACCES;
   (b) termios/winsize ioctls on a pty master = ENOTTY on macOS (Linux
   targets the slave's ldisc). Fix: real grantpt+unlockpt; on ENOTTY,
   retry ioctl on transiently-opened slave (pty_master_open_slave in
   syscall.rs). TCSETS now traced under FAKELINUX_TRACE.
   Verified live in pty-5 (scratch zsh, can kill): straight columns,
   onlcr intact after exit. **382 tests green.**
   NOTE: working pty means dpkg children's loader spam is now VISIBLE
   in apt output — FAKELINUX_QUIET wishlist item moved up.

**ext-deps attempt #3 PROGRESSING (pty-2, /tmp/fakelinux-dbg binary —
does NOT have today's two fixes; don't swap mid-build):**
- daq DONE (.daq.install.ok ~13:13) — got past attempt-#2 wall #1.
- rdma-core configuring now (cmake, clang detect ~13:15) — THE critical
  test: its bitmap_test AdvSIMD panic killed attempt #2 (fixed eb867e0).
- then dpdk (venv/ensurepip was the other crasher, also fixed).
- Markers: /tmp/ext-deps.log + /tmp/ext-deps.done (DONE_RC=…) in
  container = ubuntu-rootfs/tmp/. Monitor b3opr8h00 watches done-marker
  + panic signatures + stall.
- After DONE_RC=0: `make build` (UNATTENDED=y DEBIAN_FRONTEND=
  noninteractive PKG_VERSION=26.10 PKG_SUFFIX=0), then make run.

## REFRESH #11 STATUS (older)

**ext-deps attempt #2 DONE_RC=2 — both blockers FIXED (eb867e0):**
1. clang `ld2 {v0.2d,v1.2d},[x18]` (rdma-core bitmap_test) → trap_handler
   PANIC: AdvSIMD struct ld/st = EmulClass::Other, trampoline blanket-
   rejected it. Now trampolined (is_simd_ldst_struct; only Rn/Rm are
   GPRs). + rt_sigpending(136) implemented (ninja noise).
2. dpdk meson-venv ensurepip "disabled for system python": execve
   replaced guest argv[0] with the resolved path → venv python never
   found pyvenv.cfg. Fix: FAKELINUX_ARGV0 carries original argv[0]
   across re-exec. ensurepip now installs pip-24.0 RC=0.

**SESSION HIGHLIGHTS (all committed): gcc WORKS (0e44c32) + top WORKS
(eb84f4e).** gcc cc1 ICE = .rodata pointer-fixup corrupting switch jump
tables; fix = code-idiom detection (dispatch load+add+br, bound from the
cmp ON THE INDEX REGISTER, no-cmp → no exclusion — the no-cmp 4K
fallback swallowed CPython frozen-bytecode pointers → ensurepip
SIGKILL regression, fixed same commit). Lazy exec reloc now also runs
in the signal forwarder (guest SIGSEGV handlers used to kill it).
top: real /proc/stat (host_processor_info), loadavg, per-pid stats
(proc_pid_rusage + KERN_PROCARGS2 comm), virtual /proc files now
re-readable (lseek(0) REGENERATES content — libproc2 rewind+fread).
379 tests green. Memory file project_et_exec_relocation updated.

**IN FLIGHT: ext-deps attempt #3 in pty-2** (container on eb867e0
binary; target/release == /tmp/fakelinux-dbg now). Same markers
(/tmp/ext-deps.log + ext-deps.done). dh clean wipes _build each run →
daq rebuilds from scratch (~1h configure), then rdma-core (bitmap_test
was the crasher), then dpdk (venv was the crasher). Monitor b3opr8h00
watches done-marker + panic/ICE signatures + 15-min stall.
- After DONE_RC=0: `make build` (same env), then make run.
- Known quirk: /proc lists ALL containers' processes (top shows other
  container's bash) — pidns isolation TODO if it confuses anything.

## REFRESH #10 STATUS (older)

**ext-deps attempt #1 DONE_RC=2: dpdk extract failed — FIXED (2206b8b).**
GNU tar uses **fchmodat2 (syscall 452)** w/ AT_SYMLINK_NOFOLLOW; ENOSYS
→ tar followed dpdk-tarball symlinks (doc/api/dts/custom.css) → ELOOP
→ tar exit 2. Implemented 452: Linux flag 0x100 → macOS 0x20 + nofollow
path resolution. TDD (symlink mode test), 364 tests green.

**IN FLIGHT: ext-deps rerun in pty-2** (container relaunched on new
binary, same command/markers as #9: /tmp/ext-deps.log + ext-deps.done).
daq stamps survived → resumes at dpdk. Watchers: persistent Monitor
(done-marker + 15-min stall detector) + bg until-loop for
.dpdk.extract.ok. Partial src-dpdk was rm'd before rerun.
- write(1) EAGAIN storm in old log = guest-requested nonblock stdout
  (F_SETFL IS translated) — noise, not a bug; daq built through it.
- Perf sampled: short-lived build procs spend most time in _sigtramp
  (SIGILL storm) + patch_new_code. Known; fix = more x18 trampoline
  coverage, NOT now (don't swap binary mid-build!).
- FAKELINUX_QUIET deferred until build finishes (cargo build would
  swap binary under running build's exec'd children).
- After DONE_RC=0: `make build` (same UNATTENDED/PKG_VERSION env),
  then make run.

## REFRESH #9 STATUS (older)

**install-dep DONE_RC=0** (45700ae fchmodat garbage-x3, 0d0981a TMPDIR
leak — see #8 below). Then install-ext-deps blockers, all fixed:
1. Shallow clone has no tags → empty version. Fixed two consumers:
   `src/scripts/.version` file (v26.10-rc0-0-gf373c82) + env overrides
   `PKG_VERSION=26.10 PKG_SUFFIX=0` (build_common.mk uses ?=).
2. STALE deb/debian/changelog with empty version survived the failed
   run (rule only regenerates when older than Makefile; git clean only
   on success). Deleted it once; regenerated fine as (26.10-0).
3. **splice(76) implemented** (097470c): GNU grep splices stdin→stdout,
   ENOSYS broke autom4te's m4 check → daq configure failed. Also
   sync_file_range(84) = success no-op. 362 tests green.

**IN FLIGHT: install-ext-deps running in pty-2** (container bash
/root/vpp, binary w/ splice). Command pattern:
`UNATTENDED=y DEBIAN_FRONTEND=noninteractive PKG_VERSION=26.10
PKG_SUFFIX=0 make install-ext-deps > /tmp/ext-deps.log 2>&1; echo
DONE_RC=$? > /tmp/ext-deps.done` — daq configure was at check ~151/?
at 09:42, each conftest = slow emulated clang (~15s). EXPECT HOURS for
daq→rdma-core→xdp-tools→DPDK. Watch _build tree mtime, NOT just
ext-deps.log (configure writes daq.config.log etc.).
- After DONE_RC=0: `make build` (same UNATTENDED env), then make run.
- PERF side quest: sample slow clang conftests — is it x18 UDF SIGILL
  storm? (git block_sha1 precedent.) A FAKELINUX_QUIET would also
  help logs.
- Container relaunch incantation (bash checks isatty(stderr) AT
  STARTUP): `FAKELINUX_ROOT=ubuntu-rootfs ./target/release/fakelinux
  --container ubuntu-rootfs/bin/bash -c 'exec /bin/bash -i 2>&1'
  2>/tmp/container-stderr.log`; then in container
  `cd /root/vpp && export HOME=/root`. Terminal garbled → [CTRL+C],
  `stty sane; printf '\033c'`.

Side quests queued: Rust in container, Claude Code in container.

## REFRESH #8 STATUS (older)

**install-dep DONE_RC=2 post-mortem — both root causes FIXED, committed:**
- 45700ae fix(fchmodat): Linux syscall 53 has NO flags arg; we passed
  garbage x3 → macOS EINVAL → masked as success → dpkg's mkdir(0)+chmod
  left .dpkg-new dirs mode 000 → renameat EACCES (man-db failure).
  Also made test_eh_frame_on_libcrypto content-based (apt upgraded the
  rootfs libcrypto and stale offsets broke it).
- 0d0981a fix(env): strip host TMPDIR/__CF_USER_TEXT_ENCODING/XPC_*
  from guest env (dictionaries-common postinst died on mktemp under
  /var/folders/...). 360 tests green.
- Perl debs' "not a tar archive": NOT reproducible in isolation
  (5x clean). Watch the rerun; if it recurs it's load-dependent —
  suspect pipe/fd under SIGCHLD storm.

**IN FLIGHT: install-dep RERUN in pty-2** (container bash, /root/vpp,
fresh binary w/ both fixes; dpkg --configure -a was clean, FIX_RC=0).
Same marker pattern: /tmp/install-dep.log + /tmp/install-dep.done
(DONE_RC=…). Host watcher + 6-min stall detector running in background.
- WHEN DONE_RC=0: `UNATTENDED=y DEBIAN_FRONTEND=noninteractive make
  install-ext-deps` (same log pattern), then `make build`, then
  `make run`/`make test`.
- TERMINAL GOTCHA: bash checks isatty(stderr) AT STARTUP for
  interactivity. To keep fakelinux spam out of the pty, launch:
  `fakelinux --container ubuntu-rootfs/bin/bash -c 'exec /bin/bash -i
  2>&1' 2>/tmp/container-stderr.log`. If pty garbles: [CTRL+C] then
  `stty sane; printf '\033c'`.
- Possible nicety queued: FAKELINUX_QUIET env to gate the ~24
  eprintln "fakelinux: …" sites.

Side quests queued: Rust in container, Claude Code in container (needs
nodejs; user gives API key).

CONTEXT RESET PROTOCOL: watch pty-1 for context warning → finish
activity → update this file → stop own background tasks/monitors (else
/clear hangs!) → self-inject /clear + continuation prompt via tttt.

## REFRESH #7 STATUS (older)

**Committed since #6** (all on `testing`, 358 tests green):
- afd5a6a fix(exec): CLOEXEC re-applied before execve (py3compile deadlock)
- 4436232 fix(ppoll): sigmask honored + chunked wait + HostSigUnblock
- latest  fix(pselect6/epoll_pwait): same wait discipline as ppoll
- sudoers drop-in `etc/sudoers.d/fakelinux-no-pty` committed.

**IN FLIGHT RIGHT NOW: `UNATTENDED=y DEBIAN_FRONTEND=noninteractive
make install-dep` running in pty-2** (container bash, /root/vpp).
- Log: container `/tmp/install-dep.log`; on finish writes
  `/tmp/install-dep.done` containing `DONE_RC=<rc>`.
- debconf set to Noninteractive via debconf-set-selections (iperf3's
  "start as daemon?" prompt hung the previous run — interactive debconf
  reads /dev/tty which never gets pty input; pgroups broken: setpgid
  errno 3, Ctrl-C doesn't propagate — kill containers from HOST).
- WHEN DONE_RC=0: `UNATTENDED=y DEBIAN_FRONTEND=noninteractive make
  install-ext-deps` (same log pattern), then `make build`, then
  `make run`/`make test`. If DONE_RC≠0: read log tail, likely another
  emulation bug — sample stuck pids from host, check do_read/ppoll.
- If a kill was needed: `dpkg --configure -a` (use DEBIAN_FRONTEND=
  noninteractive) then rerun install-dep (idempotent).

Side quests queued: Rust in container, Claude Code in container (needs
nodejs; user gives API key).

CONTEXT RESET PROTOCOL (used to produce this refresh): watch pty-1 for
context warning → finish activity → update this file → stop own
background tasks/monitors (else /clear hangs!) → self-inject /clear +
continuation prompt via tttt.

## REFRESH #6 STATUS (older)

**py3compile pipe deadlock FIXED** (afd5a6a): it was NOT a pipe bug — the
CLOEXEC errpipe of CPython subprocess survived execve because FD_CLOEXEC
(stripped before macOS fork) was never re-applied at exec. Parent's Popen()
read the errpipe forever. Fix: reapply_saved_cloexec_for_exec() before both
execve sites + FORK_SAVED_CLOEXEC.clear_fd() on close/dup/dup3/F_SETFD.
`dpkg --configure -a` then ran CLEAN (exit 0).

**sudo ppoll hang FIXED** (4436232): sudo slept forever in poll() with a
zombie child after apt-get update. Two stacked bugs: (1) do_ppoll ignored
the sigmask arg (sudo relies on ppoll atomically unblocking SIGCHLD);
(2) do_ppoll runs inside the SIGILL trap handler whose sa_mask blocks ALL
host signals, so SIGCHLD couldn't even be queued as pending during the
wait. Fix: ppoll_mask_begin/end (with TIF_RESTORE_SIGMASK-style sigframe
override), chunked 100 ms poll loop, pthread_sigmask unblock around the
wait. NOTE: do_pselect6 and epoll_pwait likely have the SAME bug class —
fix the same way if something hangs in them (sudo only needed ppoll).

**sudoers drop-in added** (rootfs, uncommitted rootfs change):
`ubuntu-rootfs/etc/sudoers.d/fakelinux-no-pty` = `Defaults !use_pty`
(sudo tried to allocate a pty → "Permission denied"; no /dev/ptmx emul).

**358 tests green.** Container shell in pty-2 (fresh binary).

**IN FLIGHT: `UNATTENDED=y make install-dep` rerunning in pty-2**
(log: container /tmp/install-dep.log; completion marker
/tmp/install-dep.done with DONE_RC=…; host-side watcher task running).
When DONE_RC=0 → task #3: `UNATTENDED=y make install-ext-deps`, then
`make build` (logs long — tail), `make run`/`make test`.
If it hangs again: sample the stuck pair, check for ppoll/pselect/epoll
or another CLOEXEC-ish fd leak; old killed-apt state may need another
`dpkg --configure -a`.

Side quests queued: Rust in container, Claude Code in container (needs
nodejs; user gives API key).

CONTEXT RESET PROTOCOL (user-approved): watch pty-1 for context warning →
finish activity → update this file → wire heartbeat → self-inject /clear.

## REFRESH #5 STATUS (older)

**vpp git fsck: OK** (exit 0, FSCK_OK). Task #1 done.

**Task #2 build VPP — in progress.** User directives (sent live):
`UNATTENDED=y make install-dep`, then `UNATTENDED=y make install-ext-deps`,
then `make build`, then `make run` (or `make test` "if adventurous").

Done so far (committed 6788b41 + earlier):
1. **Case-insensitive APFS vs linux-libc-dev**: netfilter headers have 8
   case-colliding pairs (xt_connmark.h/xt_CONNMARK.h…) → dpkg unpack
   ENOENT. Fixed via dpkg path-exclude conffile in rootfs:
   `ubuntu-rootfs/etc/dpkg/dpkg.cfg.d/fakelinux-case-collisions`
   (excludes the 8 uppercase variants; VPP references none).
   REAL fix later: case-sensitive APFS volume for rootfs.
   WATCH OUT: other packages may hit new case collisions — same symptom
   ("unable to install new version of X: No such file or directory").
2. **sudo works now**: stat leaked host uid 501; sudo demands root-owned
   /etc/sudoers. Fix 6788b41: creds::map_host_uid/gid (own host id→0,
   else 65534) in mac_stat_to_linux + statx. 354 tests green.
   Also added `127.0.1.1 fakelinux` to rootfs /etc/hosts.
3. build-essential + sudo installed in container.

**CURRENT BUG — install-dep HUNG (killed, must fix then rerun).**
`UNATTENDED=y make install-dep` downloaded all 279 pkgs fine, then HUNG
6h at 0% CPU in `dpkg --configure python3-minimal` →
postinst → py3compile → `python3.12 -m py_compile -`. PIPE DEADLOCK:
- parent (py3compile) blocked in do_read (sampled: trap_handler →
  do_read → read) on fd 12 (pipe B from child fd 13 — multiprocessing
  response channel);
- child (py_compile -) blocked in do_read on fd 0 (pipe A from parent
  fd 11 = its stdin).
py3compile (/usr/bin/py3compile:156-169) uses Popen(bufsize=0,
stdin=PIPE, close_fds=True) + a second pipe (STDINS[version].send(fn),
line 219). Each side waits for data the other side thinks it sent →
suspect fakelinux pipe read/write bug (lost write? signal-interrupted
read not restarted? close_fds + fd translation?).
REPRO (likely): in container `dpkg --configure python3-minimal` or
just `echo /usr/lib/python3.12/os.py | python3.12 -m py_compile -`
style two-process pipe feeding; or run py3compile by hand.
TDD it. The killed apt left dpkg half-configured — after fix:
`dpkg --configure -a` then rerun install-dep (idempotent).
THEN: `UNATTENDED=y make install-ext-deps` (user asked),
then `make build` (logs long — tail), then `make run`/`make test`.

Side quests queued: TaskList #3 Rust in container, #4 Claude Code in
container (needs nodejs; user gives API key).

CONTEXT RESET PROTOCOL (user-approved): watch pty-1 for context warning →
finish activity → update this file → wire heartbeat → self-inject /clear.

## REFRESH #4 STATUS (older)

ALL COMMITTED through "fix(rusage)…", 350 tests green. Today's fixes:
1. **TLS WORKS.** Two bugs: (a) `ins v0.b[7], w18` (AdvSIMD copy) panicked
   trap_handler → new emul_simd_copy in trap.rs (0b1192b); (b) nettle
   SHA-256/512 K tables corrupted by x18 false-positive patches —
   runtime-mapped libs have no section headers, eh_frame strategy failed,
   fell back to whole-R-X-segment patching incl. .rodata. Fixed:
   PT_GNU_EH_FRAME → .eh_frame_hdr → FDE parser in elf.rs.
   python ssl → TLSv1.3; gnutls-cli stdio.be (USER'S OWN SERVER, good for
   https tests) → handshake completed.
2. Debug spam gated behind FAKELINUX_TRACE (PRE/POST_FORK_LR, STACK_DUMP,
   WRITE_X30, X30_BECAME_HEAP, FORK_RETURN_PROBE, ASM_X0, FUTEX_WAKE_RESULT).
3. rusage converted properly (getrusage + wait4): i32→i64 usec,
   maxrss bytes→KB. Helper linux_rusage_bytes + 2 tests.

**vpp CLONE SUCCEEDED** (task #1): /root/vpp inside ubuntu-rootfs, 94MB,
working tree checked out (`git clone --depth 1 https://gerrit.fd.io/r/vpp`).
A `git fsck` was running in background task b5u15w73b (output:
/private/tmp/claude-501/.../tasks/b5u15w73b.output) — check/rerun:
`export HOME=/root && cd /root/vpp && git fsck` in container.
Container git needs: `export HOME=/root` + safe.directory exception
(host HOME leaks in otherwise). User has a HOST clone of vpp in pty-3
for comparison (compare git log SHAs etc.).

**PERF NOTE:** git index-pack ran at 99% CPU in trap_handler —
Ubuntu's git block_sha1 uses w18 as scratch (179 refs!); UDF-fallback
x18 instrs cost a SIGILL each. Clone finished anyway. If guest gets
slow, check `sample <pid> 2` for emulate_x18_instruction; possible
follow-up: figure out why some DataProc x18 instrs fall back instead of
trampolining (x16/x17 conflict? encode_b range?) — x18_trampoline.rs.

NEXT (TaskList): #2 build VPP (apt install make gcc cmake ninja-build
etc., then `make build` or vpp's `make install-dep` — may need universe,
which IS NOW ENABLED in container sources). #5 install Rust in container
(user: "Rust uses a lot of funky CPU opcodes, great test!").
#6 install Claude Code in container (needs nodejs; user gives API key).

Apt universe enabled in /etc/apt/sources.list.d/ubuntu.sources;
gnutls-bin + nettle-bin installed (good crypto canaries:
`printf abc | nettle-hash -a sha256` must start ba7816bf).

CONTEXT RESET PROTOCOL (user-approved, in memory feedback_clear_hang.md):
watch pty-1 for context warning → finish activity → update this file →
wire heartbeat → self-inject /clear + continuation prompt via tttt.

## REFRESH #3 STATUS (older)

DONE since #2 (committed unless noted): #3 dpkg repaired+git reinstalled
(apt exit 0); #4 symlinks fixed (85f630a, rootfs::resolve_host_path in
main.rs); AF_INET6 support added in src/net.rs (Linux AF 10 ↔ macOS 30:
do_socket domain + sockaddr family both ways, 2 tests) — **UNCOMMITTED,
test+commit first!**

CURRENT BUG (task #5 git clone vpp): TLS from guest crashes —
**Rust panic inside trap_handler → panic_cannot_unwind → abort (exit
134)** during python ssl wrap_socket after connect. Repro:
`timeout 60 env FAKELINUX_ROOT=ubuntu-rootfs ./target/release/fakelinux
--container ubuntu-rootfs/usr/bin/python3.12 -c 'import socket, ssl;
ctx=ssl.create_default_context();
s=socket.create_connection(("example.com",443),timeout=15);
t=ctx.wrap_socket(s,server_hostname="example.com"); print(t.version())'`
Likely a panicking Rust path in a syscall emulation reached via signal
handler (panic in extern "C" = cannot unwind = abort). Find the panic
message: run with RUST_BACKTRACE=full, look ABOVE the backtrace for
"panicked at" line (got cut in my capture). gnutls git clone failed
similarly ("TLS connection non-properly terminated" = our process died?
No—git's child). NOTE: user's firewall was blocking 443 earlier — OFF
now; earlier "Empty reply"/gnutls failures may have been partly firewall!
RETRY git clone http://gerrit.fd.io/r/vpp after the panic fix.

Also: more ungated debug spam seen during git: POST_FORK_LR, ASM_X0,
FORK_RETURN_PROBE, X30_BECAME_HEAP, FUTEX_WAKE_RESULT, crash [sp+..]
dumps — gate behind trace like 49cee40 did.

User is around (turned firewall off). Keep history.md updated.

## REFRESH #2 STATUS (older)

DONE since refresh #1 (all committed, 338 tests green):
- **vim FULLY WORKS** (aaa62ce): gettimeofday wrote i32 tv_usec via
  passthrough; Linux expects i64 → garbage high bytes → vim deferred all
  redraws. User-confirmed on real terminal.
- **python3.12 WORKS** (f7319ff): (a) lazy_reloc_pick_register in
  trap.rs decodes faulting load/store and fixes the right register;
  (b) fixup_exec_rodata_pointers in loader.rs — .rodata had 6094
  unrelocated const pointers (caused 28GB mmap loop → SIGKILL);
  (c) restore per-page prot from PT_LOAD (edge page shared with .text
  needs EXEC). `python3.12 -c 'import sys,hashlib;…'` exit 0.
- Debug spam gated behind FAKELINUX_TRACE (49cee40).
- [ESC] alias committed in ../mcp-pty-server (247e02b).

USER DIRECTIVES (granted FULL AUTONOMY, gone to sleep):
1. North star: make fakelinux behave like real Linux.
   `git clone http://gerrit.fd.io/r/vpp` then BUILD VPP inside = ultimate test.
2. Keep appending narrative to history.md as you go.
3. Fun side-quests: alpine minimal rootfs; install rust in ubuntu
   container and run programs; install Claude Code in container and
   drive it (user will give API key tomorrow).
4. Optionally watch own screen via tttt to time /clear before compaction.

NEXT (task list in TaskList tool):
- #3 repair dpkg: dpkg --configure -a (python3.12-minimal was
  half-configured), reinstall git, verify apt clean exit 0.
- #4 symlink resolution through rootfs (see below).
- #5 git clone vpp (http first; gerrit may need https → certs).
- Then: try building VPP (will need make/gcc/cmake via apt).
- Sweep remaining macOS-i32-vs-Linux-i64 timeval bugs: getrusage
  (syscall.rs ~2455), wait4 rusage passthrough (thread.rs do_wait4).

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
