# Building and running VPP under fakelinux

[VPP](https://fd.io/) (the FD.io Vector Packet Processor) is the project's
flagship end-to-end example: a large, real C codebase that compiles itself and
runs as a userspace dataplane. Getting it to build *and run* inside fakelinux
exercises a huge surface of the Linux ABI — apt/dpkg, gcc, cmake/ninja, threads,
hugepage-style shared memory, epoll, AF_UNIX, netlink, and more.

## TL;DR

```sh
scripts/build-vpp.sh        # set up rootfs, build, then verify it runs
```

That single command:

1. builds `fakelinux` (release) if needed;
2. pulls `ubuntu:24.04` into `roots/ubuntu` and runs the build with
   `FAKELINUX_CASEFOLD=1` so case-only-colliding filenames work on macOS's normal
   case-insensitive volume — **no disk image needed** (see below);
3. inside the guest: `apt-get` installs the toolchain, clones VPP, runs
   `make install-dep` and `make build`;
4. smoke-tests the resulting `vpp` binary (boots it and checks it responds).

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

## The case-sensitivity problem (and how it's solved)

macOS's default APFS is **case-insensitive**. Several Linux packages ship files
or directories whose names differ only in case, which then collapse onto one
host entry. `linux-libc-dev` (pulled in by `build-essential`) has the kernel
headers `netfilter/xt_CONNMARK.h` vs `xt_connmark.h` (and `xt_DSCP`/`xt_dscp`,
`xt_MARK`/`xt_mark`, …); `perl` ships both `pod/` and `Pod/`, `sys/` and `Sys/`.
On a case-insensitive filesystem `dpkg` fails to unpack them:

```
unable to install new version of '/usr/include/linux/netfilter/xt_connmark.h'
```

**`build-vpp.sh` solves this with `FAKELINUX_CASEFOLD=1`** (set automatically). In
case-fold mode fakelinux stores the second of two case-fold siblings under a
sentinel-prefixed, case-injective host name and decodes it on `readdir`, so both
coexist on the normal `roots/` volume — **no disk image required**. For example
the headers above end up on disk as:

```
xt_CONNMARK.h               (verbatim)
~~NAMECASE~~xt_connmark.h   (encoded sibling — decoded back on readdir)
```

This applies to every path component, so colliding *directories* (perl's
`pod`/`Pod`) work too. See `FAKELINUX_CASEFOLD` in the top-level README.

### Alternative: a case-sensitive volume

If you'd rather use a real case-sensitive filesystem, point `ROOTFS` under
`roots-cs/` and `build-vpp.sh` will create one for you:

```sh
ROOTFS=roots-cs/ubuntu scripts/build-vpp.sh
# uses scripts/make-case-sensitive-volume.sh to mount a case-sensitive APFS
# sparse image (nominal 40 GB, only uses what's needed) at roots-cs/.
# Detach later with: hdiutil detach roots-cs
```

> Simple guests that don't install case-colliding files (e.g. Alpine, or just
> running a prebuilt binary) need neither — the normal `roots/` is fine.

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
FAKELINUX_ROOT=roots/ubuntu FAKELINUX_PAGESZ=16384 \
  ./target/release/fakelinux --container \
  roots/ubuntu/root/vpp/build-root/install-vpp_debug-native/vpp/bin/vpp \
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
