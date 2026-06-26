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

Build and run can be done separately:

```sh
scripts/build-vpp.sh build      # just compile
scripts/build-vpp.sh run        # just run what was built
scripts/build-vpp.sh shell      # interactive guest shell in the rootfs
```

The first build is long (it compiles all of VPP under emulation). Re-builds are
incremental and ccache-backed, so iterating is fast.

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

## What the build needs (and how fakelinux provides it)

- **Networking / DNS.** OCI images ship no `/etc/resolv.conf`; `fetch-rootfs.sh`
  writes a default resolver so `apt` can reach the archive.
- **apt cache sizing.** The full Ubuntu index overflows apt's default mmap cache;
  `fetch-rootfs.sh` drops an `apt.conf.d/99fakelinux` raising `APT::Cache-Start`.
- **Transient dpkg flakes.** Occasionally a postinst hits a fork hiccup under
  emulation; the build script retries and heals partial state with
  `dpkg --configure -a`.

## Running it

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
