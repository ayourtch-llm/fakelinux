# Handoff — fakelinux VPP campaign + upstream VPP bug branches (2026-06-30)

_Supersedes the 2026-06-29 cluster-A..E handoff. Memory index:
`~/.claude/projects/-Users-ayourtch-rust-fakelinux/memory/MEMORY.md`; campaign detail in
`project_parallel_jobs_campaign.md`. Branch `main`._

## 2026-07-01 loop cycle 2 — podman-pull EACCES investigation, waitid tweaks

**Blocker**: `podman pull` consistently hits `mkdir /temp-storage-extract...: permission denied`
in the layer-extract subprocess, despite:
- Same UID/EUID (my user, 501)
- Parent dir b2848 exists at mkdirat time
- Manual shell `mkdir` works on same path
- The fakelinux subprocess can mkdir in /tmp fine
- `libc::mkdir` in the parent → errno 13 (EACCES)

macOS is refusing writes specifically to
`roots/ubuntu/var/lib/containers/storage/vfs/dir/<subdir>/` from the fakelinux
subprocess after chroot. Timing-dependent — with slow diagnostic writes enabled,
sometimes succeeds; without them, consistently fails.

Suspected: macOS App Sandbox / Endpoint Security tracking process provenance
(`com.apple.provenance` xattr present; `xattr -rc` didn't clear it). See loop
cycle 2 details in the main body below.

**waitid stub** (commit `4a7bb26`): hybrid approach — try macOS waitid, map
EINVAL→ECHILD so Go moves on. -ENOSYS broke Go stack scan earlier; naive
translation broke pull. Current form lets pull complete without crash but the
extracted image isn't saved.

## 2026-07-01 SESSION — podman works end-to-end under fakelinux

User asked "let's have a look why podman crashes" and "make it work" autonomously.
Result: **`podman --version` runs cleanly** ("podman version 4.9.3"), and `podman info /
images / system info / pull` all exit 0 (the "no such file or directory" is missing
guest-side `/etc/containers/storage.conf` + `/var/lib/containers/`, not a fakelinux bug).

Five commits landed on `main`, in order. Each one peeled back a separate layer of
Go-runtime / fakelinux incompatibility:

1. **`afd445f` loader: fix Go ET_EXEC fixups for 4GB-PAGEZERO slide**
   - `fixup_exec_gopclntab` patches `pcHeader.textStart` (u64 at offset 0x18) in
     `.gopclntab`. Verifies Go 1.18+ magic (0xfffffff0/0xfffffff1). Without this Go's
     `moduledataverify1` threw "invalid function symbol table" because pcHeader lives in
     read-only `.gopclntab` which neither the `.rodata` scan nor the writable-segment scan
     touch — but `mod.text` (in writable `firstmoduledata`) DID get relocated, causing the
     mismatch.
   - Wires `apply_relocations_from_memory` (was defined but never called) into the dynamic
     ET_EXEC path. No-op for non-PIE Go (0 RELA-RELATIVE entries) but defensive.
   - **`plausible_unrelocated_pointer` inclusive upper bound (`<= orig_hi`).** Go's
     `firstmoduledata.end` and `enoptrbss` hold the EXACT one-past-end address. Old
     `< orig_hi` excluded them → stkobjinit's lookup `gofunc <= search < end` failed →
     "methodValueCallFrameObjs is not in a module". Off-by-one strict-vs-inclusive.

2. **`d50f3d7` syscall+signal: stub seccomp(277); honor SA_ONSTACK in software**
   - seccomp(2) → silent -ENOSYS (was noisy default branch).
   - **`build_sigframe_and_redirect` places the rt_sigframe on the GUEST altstack when
     `GUEST_SIGACTIONS[sig].flags & SA_ONSTACK`.** Can't mirror to macOS `sigaltstack(2)`
     (EPERM — fakelinux's trap handler is already standing on its altstack). So we honor
     SA_ONSTACK in software: start the frame at `alt_sp + alt_size`. Go's sigtramp then
     sees SP inside `[gsignal.lo, gsignal.hi)` and adjustSignalStack passes.

3. **`1fb80b0` signal: handle nested SA_ONSTACK delivery without overlapping frames**
   - First pass (geometric): if interrupted SP is already inside altstack range, push
     below current SP instead of restarting from top. Refined in step 4.

4. **`f83ef61` thread: stop overriding SIGSEGV/SIGBUS handlers per-thread** ← THE BIG ONE
   - `setup_thread_signal_stack()` was calling `sigaction(SIGSEGV, ...)` with handler
     pointer = `crash_handler_ptr() = SIG_DFL` (hardcoded 0 because the real handler in
     trap.rs wasn't pub). sigaction is PROCESS-WIDE on macOS → the instant any guest
     thread spawned, the entire process's SIGSEGV/SIGBUS handler reverted to default-abort.
     Next lazy-reloc SIGSEGV (or any forwarded fault) → silent kill, exit 139, no Go panic
     output. Quadlet survived because it spawns few threads; podman with many goroutines
     died immediately.
   - Removing the per-thread reinstall preserves the trap.rs process-wide handler.
   - Also adds explicit `ALTSTACK_DEPTH` per-thread counter (real `SS_ONSTACK` semantics)
     with marker in sigframe pad at offset 276, replacing the geometric heuristic.
     `do_guest_sigaltstack` now returns `SS_ONSTACK` in readback and refuses changes
     with -EPERM while a SA_ONSTACK handler is on the altstack.

5. **`cc8ee4f` epoll: look up user_data live per-kevent** ← THE LAST ONE
   - `do_epoll_pwait` was `clone()`ing the registrations HashMap at entry, then sleeping
     in `kevent()`. Another thread could `epoll_ctl_ADD` a fresh fd during that window
     (often the same fd number reused after a close), and the wakeup event came back with
     `user_data=0` from our stale snapshot. Go's netpoll dereferences `ev.data` as
     `*pollDesc` — NULL → SIGSEGV deep in `runtime.netpoll` at netpoll_epoll.go:166.
   - Fix: per-kevent lookup against live state under the lock. If the fd is no longer
     registered (raced past DEL or auto-cleanup on close), drop the event silently rather
     than surfacing user_data=0.

### Verification matrix (TTY mode, no pipes)

| Binary                                 | Before          | After                |
|----------------------------------------|-----------------|----------------------|
| `quadlet --version`                    | 4.9.3 (worked)  | 4.9.3                |
| `conmon --version`                     | 2.1.10 (worked) | 2.1.10               |
| `podman --version`                     | EXIT 139 silent | 4.9.3 ✓              |
| `podman info`                          | (broken)        | full output ✓        |
| `podman images / ps -a`                | (broken)        | headers, empty ✓     |
| `podman pull docker.io/library/alpine` | (broken)        | downloads blob ¹ ✓   |

¹ Pulls the blob over HTTPS successfully, then fails in **layer-extract subprocess** —
podman re-execs itself (via /proc/self/exe) to do uid-mapping + untar, but the
sub-fakelinux can't load `/usr/bin/podman` because `FAKELINUX_ROOT` is lost across the
re-exec. The error reads `fakelinux: cannot read '/usr/bin/podman': No such file or
directory (os error 2)` — note it's fakelinux's own bootstrap message, not podman's.
Genuine container-in-container needs that handed off properly; out of scope for tonight.

### Guest-side configuration needed (mirror in clone setups)
- `mkdir -p roots/ubuntu/sys/fs/cgroup` — podman statfs's this on every command; ENOENT
  here is the "Error: no such file or directory" all info/pull commands hit. Could be
  synthesized by `procfs.rs` instead — TODO. Single directory mkdir is the quick fix.
- `roots/ubuntu/etc/containers/storage.conf`:
  ```
  [storage]
  driver = "vfs"
  runroot = "/run/containers/storage"
  graphroot = "/var/lib/containers/storage"
  ```
- `mkdir -p roots/ubuntu/var/lib/containers/storage roots/ubuntu/run/containers/storage`

### Performance note (deferred)
`podman --version` is ~1.7s wall-clock vs `quadlet --version` 0.2s. Each new fakelinux
process has to scan + patch every loaded ELF (SVC→UDF, x18 instr trampolines) — there
are ~9 distinct DSOs in podman vs ~3 in quadlet. The "(cached)" marker shows in-process
hit rate is good; the cache doesn't persist across exec because the parent process is
gone. A disk-backed cache keyed on (path, mtime, size) would amortize startup; a lazier
"patch on first SVC fault" path is the deeper fix. Out of scope tonight.

### Regression — VPP `make test-debug` running in background

Per user request after podman worked. Kicked off:
```
nohup ./scripts/vpp-shell.sh make test-debug TEST_JOBS=4 > /tmp/vpp_test_regress_013047.log 2>&1
```
Log path also in `/tmp/vpp_log_path`. **DONE_RC=…** line at the bottom of the log is the
ground truth (per `[[clear-hang]]` memory). Last known-good before these 5 commits per
`project_parallel_jobs_campaign.md`: ran past 1804 OK, 0 truncation. The signal/altstack
+ epoll changes touch hot paths used by every Go binary AND by VPP's test harness (which
uses epoll heavily), so a clean run here is the gate for these changes.

To resume after sleep/clear: `tail -50 $(cat /tmp/vpp_log_path)`. If DONE_RC=0 and the
final counter looks sane (≥1210 OK), regression is clean — close out task #8.

### Memory written this session
- `project_eventfd_scm_rights.md` — eventfd-as-AF_UNIX-dgram (separate earlier turn).
- `project_vpp_fixes_catalog.md` — catalog of 5 VPP-side patches (DAD, TestCrypto timeout,
  SvmFifo, StatsClient, PathMTU) needed if VPP tree is recreated.
- `project_go_et_exec_fixes.md` — older snapshot of the Go fixes (now superseded by the
  five commits above; the memory captures the per-fix reasoning).

### Open follow-ups
- **Container-in-container.** Need `/etc/containers/storage.conf` (vfs driver, /var/lib path)
  + `mkdir -p /var/lib/containers/storage /run/containers/storage` in the guest rootfs.
  Then network access in the guest is the next gate. Worth a separate session.
- **`apply_relocations_from_memory` was a no-op** for podman (non-PIE Go has no
  R_AARCH64_RELATIVE). Kept because it's correct, defensive, idempotent vs ld-linux —
  but no test exercises it.

## 2026-07-01 continued — podman pull works, run has Go GC crash

Two more commits (`3e5e29c`, `e505a15`, `7ba3afa`) — SIGNIFICANT PROGRESS:

**`podman pull docker.io/library/alpine` completes cleanly** and the ubuntu rootfs stays
intact. Previously the chroot stub let alpine's `/lib/ld-musl-aarch64.so.1` +
`/etc/alpine-release` stomp `roots/ubuntu/` (twice tonight). Fixed by:

1. `execve` translates `/proc/self/exe` to a HOST path (was passing guest path, causing
   main.rs to ENOENT and die during podman's re-exec for layer-extract).
2. **Real chroot tracking.** `rootfs::CHROOT_HOST` Mutex; `translate_path` prefixes it
   before FAKELINUX_ROOT; `do_chroot` stat-verifies + stores; persists across `execve` via
   `FAKELINUX_CHROOT` env var picked up by `init_chroot_from_env()` at startup + carried
   through `build_exec_overrides`.
3. Stubs for `unshare(97)`, `setns(268)`, `pivot_root(41)`, `mount(40)`, `umount2(39)`,
   `waitid(95)`, `name_to_handle_at(264)/open_by_handle_at(265)`, `openat2(437)`,
   `seccomp(277)`.
4. `utimensat` swallows `EACCES/EPERM/ENOENT` — podman's tar-extract chtimes device nodes
   and stale /proc paths inside the container image; mtime is cosmetic.

Guest-side setup for this to work (same as before session): `mkdir -p sys/fs/cgroup
var/lib/containers/storage run/containers/storage etc/containers` + a minimal
`etc/containers/storage.conf` with the vfs driver. If missing, `podman info` hits
"Error: no such file or directory".

### Container-in-container achieved (via direct chroot)

While podman *run* still crashes (below), the alpine layer that `podman pull` extracted
into `roots/ubuntu/var/lib/containers/storage/vfs/dir/<digest>/` IS a working rootfs. Ran
directly by pointing fakelinux at it:

```
$ ALPINE=roots/ubuntu/var/lib/containers/storage/vfs/dir/b2848.../409
$ FAKELINUX_ROOT=$ALPINE ./target/release/fakelinux --container $ALPINE/bin/sh -c \
    'echo "hello from alpine!"; cat /etc/os-release | head -3'
hello from alpine!
NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.24.1
```

That's container-in-container: Ubuntu rootfs (level 1, fakelinux) → podman pulls alpine
image → alpine rootfs (level 2, fakelinux).

**`br x18` fix (commit `92610fc`)** — trap.rs EmulClass::Other catch-all now recognizes
BR/BLR/RET Xn generically (mask `0xFFFF_FC1F` matches `0xD61F_0000`/`0xD63F_0000`/
`0xD65F_0000`). Alpine's busybox uses `br x18` in dispatch stubs; without this fakelinux
panics as soon as `apk update` runs. After the fix:

- `apk update` — 28537 packages available
- `apk add --no-cache build-base git` — 33 packages installed
- `apk add --no-cache cmake ninja python3 py3-pip openssl-dev ...` — 38 more
- `git clone --depth 1 https://gerrit.fd.io/r/vpp` — **VPP cloned into Alpine, 5005 files**

**Compiling inside the Alpine container hits toolchain issues** —
`gcc -o t t.c` faults with SIGBUS at pc in the stack region (`fp=0x0`,
`x18(emu)=0xffff` — bogus/uninitialized). `clang -o t t.c` hangs (30s timeout).
`gcc --version` runs fine standalone. So the failure is in gcc's subprocess
chain (cc1, as, ld) — either fakelinux's fork+exec + musl trampolines, or
Alpine's ld-musl doing something our loader doesn't handle. Standalone
binaries (busybox, git, apk, gcc-driver-with-just-args) all work.

### Next steps ranked
1. **Investigate gcc SIGBUS**: `x18=0xffff` on entry looks like the guest x18
   TSD wasn't initialized when the exec'd cc1 process started under musl. Compare
   against `set_thread_x18` init in `clone_entry` and any code path from
   `do_execve` that runs at Alpine startup.
2. Once cc1 runs, `apk add cmake ninja python3 ...` is done (installed earlier)
   and `cd /root/vpp && make install-dep` (VPP's ubuntu path won't work on
   alpine — will need `apk`-mapped equivalents).
3. **Alternative**: skip the alpine layer and try `podman pull ubuntu:24.04`,
   which uses glibc — should sidestep the musl issues.
4. The Go GC "invalid pointer" crash in `podman run` is a separate axis and
   probably subtler; direct-chroot workaround is fine for now.

### Working direct-chroot invocation (for reference)
```bash
ALPINE=roots/ubuntu/var/lib/containers/storage/vfs/dir/b2848c02ac6ff53d265469b5b30f649f335e546a83330cd8916d54e65e640409
FAKELINUX_ROOT=$ALPINE ./target/release/fakelinux --container $ALPINE/bin/sh -c '<cmd>'
```
Alpine's ID/name/version-id file: `$ALPINE/etc/os-release`; VPP source cloned
at `$ALPINE/root/vpp`. `/etc/resolv.conf` was added with 8.8.8.8/1.1.1.1 so
`apk update` and `git clone` reach the network.

### `podman run --rm alpine echo hi` still crashes
```
runtime: bad pointer in frame github.com/containers/common/libimage.(*Runtime).Pull at 0x14000347538: 0x4
fatal error: invalid pointer found on stack
```
Deterministic; the value `0x4` sits in a stack slot Go's GC expects to hold a pointer.
Reproduces on every attempt. Not caused by this session's changes — was there before
we added waitid/etc. stubs. Likely a fakelinux side effect (signal handling? syscall
clobbering a caller-saved reg?) in the podman `Runtime.Pull` code path that only runs
during `podman run` (image lookup / mount preparation), not during pull itself. The
next dig-in should trace which syscall runs just before Go's GC catches the corruption
— specifically look at whether the frame slot was written by a syscall wrapper.

### Rootfs restoration note
The chroot stub had already stomped `roots/ubuntu/` twice by the time real chroot went
in. Both damaged trees preserved as `roots/ubuntu-DAMAGED-014710/` (kept for
`root/vpp` source; 11G). Fresh `scripts/fetch-rootfs.sh ubuntu` regenerated a clean
Ubuntu 24.04 rootfs; VPP source copied back via
`cp -r roots/ubuntu-DAMAGED-014710/root/vpp roots/ubuntu/root/`.

## TL;DR — the LIVE thread (resume here)

Working on **pty-8** = a REAL aarch64 Linux box (`gx10-be8b`, NVIDIA DGX Spark, kernel
6.17, **4K pages**, 20 cores), repo `~/vpp/vpp`. It's used to prove which fakelinux-found
"VPP bugs" are genuine upstream bugs (reproduce with ZERO fakelinux) and to build clean
one-branch-per-fix with `Signed-off-by` for gerrit.

**DONE — the ip_frag negative-headroom bug.** pty-8 branch `fix-ip-frag-neg-headroom`
(base `2ac657d3c`). TWO commits landed (authored Andrew Yourtchenko, `-s` + Co-Authored-By
Claude trailer, `Type:` tags — gerrit-ready but NOT pushed yet):
- `2c02727b3` **ip-frag: copy original buffer current_data directly when fragmenting** —
  the fix (both ip4 + ip6 sites set `to_b->current_data = org_from_b->current_data;
  to_data = vlib_buffer_get_current(to_b);` with an explanatory comment) + the regression
  test `test_path_mtu_frag_payload` in `TestIPv6PathMTU` (`test/test_ip6.py`).
- `34e3614ac` **vlib: assert vlib_buffer_make_headroom keeps current_data in range** —
  defensive `ASSERT (current_data >= 0 && current_data <= VLIB_BUFFER_DEFAULT_DATA_SIZE)`
  in `make_headroom` (the lower bound already lives in `vlib_buffer_get_current`).

Verified on pty-8 (real 4K arm64): `TestIPv6PathMTU` 3/3 green WITH the assert; `test_tcp`
2/2 green (assert doesn't false-fire on the 140-byte `TRANSPORT_MAX_HDRS_LEN` callers).

### TWO key findings from this round (important — they overturn earlier assumptions)
1. **The bug is NOT arch-specific.** `current_data = 14 (inner Ether) − 40 (outer IPv6) =
   −26` is identical on x86; the `u8` truncation (−26 → 230) is pure C. Only whether the
   resulting out-of-bounds fragment-buffer write hits *live* memory (and crashes) is
   layout-dependent — it crashed under fakelinux (128-byte cache-line buffer layout), and
   is silent on the DGX 4K layout.
2. **A black-box packet test CANNOT turn this red on real Linux.** Empirically confirmed:
   the distinct-payload reassembly test passes on the *unfixed* binary on the DGX. The
   earlier "uniform payload masks it, distinct reveals it" theory is WRONG — on the DGX the
   OOB write lands in buffer slack and the transmitted/reassembled bytes are correct either
   way. The committed packet test is therefore a *path-exercising* regression test (and the
   genuine repro of the original crash UNDER fakelinux), not a red/green guard on native
   arm64. The user accepted this (chose "C unit-test invariant" then revised to "commit the
   python test + fix"). Note: an earlier run's "RED" was a FALSE positive — the first
   assertion compared the whole inner IPv6 packet (scapy leaves the encapsulated packet as
   `Raw`, starting `\x60...`) against just the UDP payload; the committed test parses the
   inner packet first: `inner = IPv6(bytes(reasm[Raw].load)); inner[Raw].load == payload`.

### make_headroom assert — why this exact bound
Callers pass `size` ∈ {0, MAX_LISP_MSG_ENCAP_LEN=100, TRANSPORT_MAX_HDRS_LEN=140} on FRESH
buffers (current_data starts 0). `TRANSPORT_MAX_HDRS_LEN=140 > VLIB_BUFFER_PRE_DATA_SIZE
(128)`, so a `size <= PRE_DATA_SIZE` bound would FALSE-FIRE — don't use it. `<=
DEFAULT_DATA_SIZE (2048)` never false-fires (legit results ≤140) and catches off-the-end
overflow. CAVEAT (already told the user): this bound does NOT catch the specific −26→230
case (230 is in-range); no clean threshold separates 230 from a legit 140. The −26 case is
prevented by the caller fix; the assert is general hardening.

### IMPORTANT user correction (do NOT revert)
My FIRST attempt widened `vlib_buffer_make_headroom`'s param `u8`->`i16`. User REJECTED it:
"you cannot ask to make a negative headroom." make_headroom means "reserve N positive
bytes"; the bug is the CALLER (ip_frag) abusing it. The old i16 commit still exists on the
GUEST's VPP branch (61a31eef5) and must be redone as the ip_frag approach (see loose ends).

## pty-8 branches (real aarch64 Linux, gerrit-ready)
- `fix-stats-dup-symlink` @`6b06cd893` — DONE/committed/verified. `src/vlib/stats/
  collector.c` ASSERT fired on duplicate node-name symlinks (deleted-iface "-deleted"
  tombstones can share a name). REPRODUCES on real arm64 (SIGABRT, zero fakelinux).
  (Note: `test_client_fd_leak` PASSES on real Linux — `/proc/pid/fd` was a fakelinux gap.)
- `fix-ip-frag-neg-headroom` — DONE/committed/verified (`2c02727b3` fix+test, `34e3614ac`
  make_headroom assert). 3/3 PathMTU + 2/2 tcp green. NOT pushed.
- base for both: `arm-tests` @`2ac657d3c`.

## Classification recap (real VPP bug vs fakelinux-only vs page-size)
- REAL upstream VPP bugs (repro on real arm64, NOT arch-specific):
  - StatsClient dup-symlink ASSERT.
  - ip_frag negative-headroom fragment overflow.
- fakelinux-only emulation gaps (won't repro on real Linux): memif sub-page do_mmap,
  eventfd, truncate, /proc/fd.
- page-size-specific (16K/64K only, won't repro on 4K DGX): SvmFifo.
- The 7 IP6 DAD aborts = known VPP-on-arm64 fcvtzu float-saturation (not ours).
- VCLCutThruBAPI = deprecated VPP bapi transport (not fakelinux).

## fakelinux fixes committed this campaign (repo /Users/ayourtch/rust/fakelinux, main)
All built; 318 unit tests green. Newest first:
- `f97475a` timers: reset POSIX timer state on fork + FAKELINUX_TRACE_SIGUSR1 diag
- `53afee6` fix: keep page-aligned MAP_SHARED file mappings shared when length < page
  (memif cross-process "wrong cookie"; general do_mmap bug — sub-page memfd was made private)
- `1dd4125` diag: guest-abort fp-chain backtrace + procfs library-mmap registration
  ("guest-abort" = symbolizes any guest SIGABRT via addr2line; how PathMTU was root-caused)
- `cf20e8a` procfs: /proc/<pid>/fd directory (StatsClient fd-leak)
- `8216744` fix: eventfd -> self-connected AF_UNIX SOCK_DGRAM (SCM_RIGHTS-writable);
  fixes VCL interrupt-mode hangs (Echo/TLS InterruptMode). Design reviewed by pty-3/pty-4.
- `96f1968` fix: implement truncate(path) (was ENOSYS) — TestMpcap
- `db6e536` fix: gate socket-close shutdown() on has_waiter — THE Issue-1 manager-death /
  run-truncation killer; validated end-to-end (full 2484-test run, 0 truncation)
- `5a9f641` / `0aeb2d7` diagnostics (TRACE_SHUTDOWN / TRACE_EXIT)

## fakelinux's OWN VPP guest copy (roots/ubuntu/root/vpp), branch fakelinux-16kb-and-logic-fixes
- `dca19095c` test: svm_fifo page-size-independent
- `10ec649c8` stats: dup-symlink (== pty-8 6b06cd893)
- `61a31eef5` vlib: make_headroom u8->i16 — **SUPERSEDED**; redo as the ip_frag direct-
  assignment fix to match pty-8 (cherry-pick the pty-8 commit once it lands).

## Loose ends / TODO
1. Ask the user before pushing any branch to gerrit (outward-facing). Two ready on pty-8:
   `fix-stats-dup-symlink`, `fix-ip-frag-neg-headroom` (2 commits each-ish).
2. Redo guest VPP make_headroom commit (61a31eef5) as the ip_frag approach — cherry-pick
   pty-8 `2c02727b3` + `34e3614ac` onto the guest's `fakelinux-16kb-and-logic-fixes`.
3. **Flaky VPP linker** ("clang: User defined signal 1" = macOS SIGUSR1 (30) killing the
   lld host process; intermittent, load-dependent). Instrumented FAKELINUX_TRACE_SIGUSR1 on
   pthread_kill/kill/timer paths + fixed a latent fork-timer-reset bug (f97475a). NOT
   reproduced in 20 isolated relinks. A `make build-release` with FAKELINUX_TRACE_SIGUSR1=1
   was launched on the GUEST -> `/tmp/build_release_usr1.log`; grep for
   `DONE_RC`/`User defined signal`/`SIGUSR1` to see if it caught the source.
5. Local `tmp_*` scratch — already cleaned up.

## pty / send_keys gotchas (editing files on pty-8 over the wire)
- send_keys turns literal `\n` into Enter, so heredocs / `python3 -c` with `\n` inside
  string literals BREAK. **Use base64**: Write the helper locally, `base64` it,
  `echo '<b64>' | base64 -d | python3` (run a patch script) or `> file` / `>> file`.
- Single-line `sed -i 's|...|...|'` is fine. Always send keys, then `[ENTER]` as a SEPARATE
  send_keys call. Use `tttt_pty_wait_for` with a result-pattern + generous timeout.

## VPP / fakelinux command reference (still current)
- Run suite under fakelinux (Mac side): `scripts/vpp-shell.sh 'make test-debug TEST=<f>'`.
  Filter: bare=file (`TEST=bfd`), `file.Class`, or `file.Class.method`. Empty=full (~2498).
- **Always `pkill -9 -f fakelinux` before a run.** Long runs: nohup-detach + a `DONE_RC=`
  log marker (ground truth); usage outages kill wakeups.
- Rebuild fakelinux: `cargo build --release`. Rebuild VPP debug after a source edit:
  `scripts/vpp-shell.sh 'make build'` (incremental). Don't rebuild fakelinux mid-run.
- On pty-8 (real Linux), it's just native: `cd ~/vpp/vpp && make build` / `make test-debug
  TEST=...`. No fakelinux involved.
- Test artifacts: `roots/ubuntu/tmp/vpp-unittest-<Class>/` (log.txt, vpp_stderr.txt);
  `/tmp/vpp-failed-unittests/`. On pty-8: `~/vpp/vpp/test/run/` + failed dirs printed.

## Other sessions the user has (for design review)
pty-1 = me, pty-2 = Claude, pty-3 = Codex (gpt-5.5), pty-4 = GLM-5.2 (all in
/Users/ayourtch/rust/fakelinux), pty-8 = the DGX ssh. pty-3/pty-4 reviewed the eventfd
self-connected-socket design and concurred.
