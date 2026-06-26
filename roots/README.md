# Guest root filesystems

fakelinux runs a Linux binary against a *guest root filesystem* — a directory
tree containing the distro's `/bin`, `/lib`, `/usr`, `/etc`, … You point
`FAKELINUX_ROOT` at one of these trees. They are **not** checked into the
repository (they are large, and contain third-party distro binaries); this
directory is where they live locally.

## Fetching one

Use the helper script — it pulls the `linux/arm64` variant of an OCI image and
extracts it here, with no Docker required (it uses the project's own
`fakelinux-pull`):

```sh
scripts/fetch-rootfs.sh ubuntu          # ubuntu:24.04  -> roots/ubuntu
scripts/fetch-rootfs.sh alpine          # alpine:latest -> roots/alpine
scripts/fetch-rootfs.sh debian          # debian:sid    -> roots/debian
scripts/fetch-rootfs.sh python          # python:3.12-slim -> roots/python
scripts/fetch-rootfs.sh noble ubuntu:24.04   # custom name + any image ref
```

You can also populate a tree any other way (e.g. `docker export`,
`debootstrap`) — just drop it under `roots/<name>/`.

## Using one

```sh
FAKELINUX_ROOT=roots/ubuntu ./target/release/fakelinux --container roots/ubuntu/bin/bash
```

Pass the guest binary as a **host path that includes the `roots/<name>` prefix**
(`roots/ubuntu/bin/bash`, not `/bin/bash`); fakelinux strips the prefix to derive
the guest's own view of the path.

`--container` gives the guest a virtual PID namespace (PID 1, virtual root).
`FAKELINUX_ROOT` also serves as the sysroot for the dynamic loader and shared
libraries; set `FAKELINUX_SYSROOT` separately only if you need them to differ.

## Layout

Each subdirectory here is one independent guest tree, e.g.:

```
roots/
  ubuntu/   # ubuntu:24.04
  alpine/   # alpine:latest
  python/   # python:3.12-slim
```

Everything under `roots/` except this README is gitignored.
