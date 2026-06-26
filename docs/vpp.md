# Building and running VPP under fakelinux

[VPP](https://fd.io/) (the FD.io Vector Packet Processor) is the project's
flagship end-to-end example: a large, real C codebase that compiles itself and
runs as a userspace dataplane. Getting it to build *and run* inside fakelinux
exercises a huge surface of the Linux ABI — apt/dpkg, gcc, cmake/ninja, threads,
hugepage-style shared memory, epoll, AF_UNIX, netlink, and more.

## TL;DR

```sh
scripts/build-vpp.sh        # set up rootfs + case-sensitive volume, build, then run
```

That single command:

1. builds `fakelinux` (release) if needed;
2. creates a **case-sensitive** APFS volume at `roots-cs/` (see below) and pulls
   `ubuntu:24.04` into `roots-cs/ubuntu`;
3. inside the guest: `apt-get` installs the toolchain, clones VPP, runs
   `make install-dep` and `make build`;
4. launches the resulting `vpp` binary on its interactive CLI.

Steps can also be run individually:

```sh
scripts/build-vpp.sh build      # just compile (fetch rootfs/deps as needed)
scripts/build-vpp.sh verify     # smoke-test the built VPP (same as run-vpp.sh test)

scripts/run-vpp.sh              # run VPP with its interactive CLI (needs a TTY)
scripts/run-vpp.sh test        # automated smoke test (boot + vppctl over cli.sock)
scripts/run-vpp.sh vppctl show version    # one-off vppctl command

scripts/vpp-shell.sh           # interactive shell in /root/vpp (the build env)
scripts/vpp-shell.sh make build           # run one command in /root/vpp
```

The first build is long (it compiles all of VPP under emulation). Re-builds are
incremental and ccache-backed, so iterating is fast.

### How the smoke test works

VPP's interactive CLI needs a real terminal, so `run-vpp.sh test` instead boots
VPP as a service (`cli-listen /run/vpp/cli.sock`, no `interactive`) and drives it
with `vppctl` from a *separate* fakelinux process over the Unix socket. It checks
the version banner, then creates a loopback interface and assigns it an address,
confirming the dataplane responds:

```
vpp v26.10-rc0~179-g... built by root on fakelinux at ...
loop0 (up):
  L3 10.10.10.1/24
==> VPP smoke test PASSED
```

This also exercises fakelinux's AF_UNIX cross-process support (the two processes
share the guest's `/run/vpp/cli.sock`).

## Why a case-sensitive volume?

macOS's default APFS is **case-insensitive**. The Linux kernel headers shipped by
`linux-libc-dev` (a transitive dependency of `build-essential`) include files
whose names differ only in case — e.g. `netfilter/xt_CONNMARK.h` vs
`netfilter/xt_connmark.h`. On a case-insensitive filesystem these collide and
`dpkg` fails to unpack the package:

```
unable to install new version of '/usr/include/linux/netfilter/xt_connmark.h'
```

So any guest tree that installs kernel headers must live on a case-sensitive
filesystem. `build-vpp.sh` handles this automatically via:

```sh
scripts/make-case-sensitive-volume.sh roots-cs
```

which creates a case-sensitive APFS **sparse** disk image (nominal 40 GB, but it
only consumes the space actually used) and mounts it at `roots-cs/`. It is
idempotent and a no-op if the target is already case-sensitive. To detach it
later: `hdiutil detach roots-cs`.

> Simple guests that don't install kernel headers (e.g. Alpine, or just running
> a prebuilt binary) work fine on the normal case-insensitive `roots/` — the
> case-sensitive volume is only needed for from-source builds like this one.

**Alternative (no volume):** set `FAKELINUX_CASEFOLD=1` to let case-only-colliding
filenames coexist on a normal case-insensitive volume — fakelinux stores the
second sibling under a sentinel-encoded name (`~~NAMECASE~~…`) and decodes it on
readdir. This avoids the disk image entirely. `build-vpp.sh` uses the
case-sensitive volume by default (well-tested); the casefold path is newer.

## What the build needs (and how fakelinux provides it)

- **Networking / DNS.** OCI images ship no `/etc/resolv.conf`; `fetch-rootfs.sh`
  writes a default resolver so `apt` can reach the archive.
- **apt cache sizing.** The full Ubuntu index overflows apt's default mmap cache;
  `fetch-rootfs.sh` drops an `apt.conf.d/99fakelinux` raising `APT::Cache-Start`.
- **Transient dpkg flakes.** Occasionally a postinst hits a fork hiccup under
  emulation; the build script retries and heals partial state with
  `dpkg --configure -a`.

## Running it

Easiest:

```sh
scripts/run-vpp.sh            # interactive VPP CLI
```

which is equivalent to running the binary directly:

```sh
FAKELINUX_ROOT=roots-cs/ubuntu FAKELINUX_PAGESZ=16384 \
  ./target/release/fakelinux --container \
  roots-cs/ubuntu/root/vpp/build-root/install-vpp_debug-native/vpp/bin/vpp \
  'unix { nodaemon interactive cli-listen /run/vpp/cli.sock } plugins { plugin dpdk_plugin.so { disable } }'
```

`FAKELINUX_PAGESZ=16384` matters: VPP's buffer/shared-memory allocator assumes a
16 KB page (real on Asahi; emulated here). At the `vpp# ` prompt you can run
`show version`, `show interfaces`, create a loopback, assign an IP, and ping it.

The DPDK plugin is disabled (no real NICs to bind); VPP runs with its host-stack
/ virtual interfaces.

## See also

- [`docs/known-issues.md`](known-issues.md)
- [`docs/devlog/`](devlog/) — the blow-by-blow of getting VPP to run.
