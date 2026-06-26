# fakelinux

Run unmodified **aarch64 Linux ELF binaries directly on macOS (Apple Silicon)** —
no virtual machine, no Docker, no Rosetta. fakelinux is a user-space Linux
emulator: it loads a Linux executable into its own address space, emulates the
Linux syscall ABI on top of macOS, and traps the handful of ARM64 instructions
that behave differently between the two operating systems.

The host and guest share the same CPU (Apple Silicon is aarch64), so guest code
runs *natively* at full speed. Only syscalls and a few privileged/per-thread
instructions are intercepted.

> **Status:** experimental research project. It is good enough to run real,
> non-trivial software — `bash`, `apt-get update && apt-get install`, `vim`,
> `python3`, and even [VPP](https://fd.io/) (the Vector Packet Processor, with
> live packet forwarding) — but it implements ~110 syscalls and is not a
> complete or hardened Linux. Expect rough edges. See
> [`docs/known-issues.md`](docs/known-issues.md).

## How it works

fakelinux uses a **trap-and-emulate** loop built around macOS signal delivery:

1. **ELF loader** (`src/loader.rs`) maps the Linux binary (static or dynamic,
   PIE or `ET_EXEC`) and scans `.text` for instructions that must be
   intercepted, rewriting them in place to `UDF #0xF000` (an undefined
   instruction). A literal-pool-aware patcher avoids corrupting embedded data.
2. Each guest syscall is an `SVC #0`, which the patcher has turned into a `UDF`.
   Executing it raises **`SIGILL`**, which fakelinux catches.
3. The **trap handler** (`src/trap.rs`) decodes the faulting instruction and
   either emulates the Linux **syscall** (`src/syscall.rs`) or the privileged
   instruction, then resumes the guest where it left off.

Why `UDF`/`SIGILL` instead of a breakpoint? On macOS the kernel **zeroes `x18`
on every `SIGTRAP`** but preserves it for `SIGILL`. The guest needs `x18`, so we
trap with an undefined instruction. This is one of many Apple-Silicon-specific
discoveries documented in [`docs/devlog/`](docs/devlog/).

A few things also get virtualized via the same trap mechanism:

- **`MSR/MRS TPIDR_EL0`** — the thread pointer is backed by a `pthread` key, so
  guest TLS survives macOS clobbering the real register across signals.
- **`x18` accesses** — `x18` is the macOS "platform register"; the guest's value
  rides in per-thread storage.
- **`fork`/`clone` and `PROT_EXEC` `mprotect`** — deferred to a post-signal
  *trampoline* because these are unsafe to perform inside a signal handler.

### The instruction decoder is generated from ARM's official spec

The decoder is not hand-written. `build.rs` parses ARM's machine-readable
**A64 ISA XML** and generates a `(mask, value, register-fields,
emulation-class)` table at build time. This makes the decoder a faithful,
single-source-of-truth reflection of the architecture rather than a pile of
hand-tuned bit masks.

> The **generated** table is committed under `src/generated/`, so you don't need
> the ARM XML to build or run fakelinux. The XML itself is *not* bundled (it is
> ARM's copyrighted material under ARM's own license); you only need it to
> regenerate the table. See [`data/encoding/README.md`](data/encoding/README.md).

## Requirements

- **macOS on Apple Silicon** (M1 or later — aarch64 host is mandatory).
- **Rust** (stable, edition 2021) — install via [rustup](https://rustup.rs/).
- **Docker** (optional) — only to cross-compile the C test suite in `tests/`.
- An **aarch64 Linux root filesystem** if you want to run dynamically-linked
  programs (see below). None is bundled.

## Build

The generated decode table is committed under `src/generated/`, so the emulator
builds and runs out of the box — **no ARM spec download required**:

```sh
cargo build --release             # binary at target/release/fakelinux
```

You only need ARM's ISA XML if you want to *regenerate* that table (e.g. to pick
up a newer architecture release). Fetch the spec and rebuild with the
regeneration flag set:

```sh
scripts/fetch-arm-isa-xml.sh                 # downloads the latest A64 ISA XML
FAKELINUX_REGEN_DECODER=1 cargo build        # rewrites src/generated/ from the spec
```

See [`data/encoding/README.md`](data/encoding/README.md) for details.

## Usage

```
fakelinux [--container] <aarch64-linux-elf> [args...]
```

Run a static binary directly:

```sh
cargo build --release
./target/release/fakelinux ./my-static-aarch64-binary
```

Run something from a full Linux userland (dynamic binaries). Fetch an aarch64
root filesystem into `roots/` (no Docker needed — it uses the bundled
`fakelinux-pull` to pull the `linux/arm64` image and extract it), then point
`FAKELINUX_ROOT` at it and use `--container` to get a virtual PID namespace (the
guest runs as PID 1, virtual root):

```sh
scripts/fetch-rootfs.sh ubuntu        # ubuntu:24.04 -> roots/ubuntu

FAKELINUX_ROOT=roots/ubuntu \
  ./target/release/fakelinux --container roots/ubuntu/bin/bash -c "uname -a && apt-get update"
```

Pass the guest binary as a **host path that includes the `roots/<name>` prefix**
(e.g. `roots/ubuntu/bin/bash`); fakelinux strips the prefix to derive the guest's
own view of the path. See [`roots/README.md`](roots/README.md) for other distros
and details.

### Key environment variables

| Variable             | Purpose                                                          |
|----------------------|------------------------------------------------------------------|
| `FAKELINUX_ROOT`     | Path to the guest root filesystem (sets sysroot too).            |
| `FAKELINUX_SYSROOT`  | Sysroot for resolving the dynamic loader / shared libraries.     |
| `FAKELINUX_PAGESZ`   | Override the guest page size (e.g. `16384` for VPP).             |
| `FAKELINUX_CASEFOLD` | Let case-only-colliding filenames coexist on macOS's case-insensitive FS (avoids needing a case-sensitive volume). |
| `FAKELINUX_VERBOSE`  | Print fakelinux's own diagnostics (same as `-v`).                |
| `FAKELINUX_TRACE`    | Trace every emulated syscall to stderr.                          |
| `FAKELINUX_TRAP_STATS` | Print trap/emulation statistics on exit.                       |
| `FAKELINUX_WATCH`    | Software watchpoint helper for debugging guest memory.           |

(See `git grep FAKELINUX_ src/` for the full list, including tracing knobs.)

## Tests

Rust unit tests:

```sh
cargo test
```

The C integration suite cross-compiles small Linux programs (in `tests/`) with
Docker and runs each one under fakelinux, checking exit codes and output:

```sh
./tests/run_tests.sh
```

## Project layout

```
src/
  main.rs         entry point; signal-handler setup, CLI parsing
  loader.rs       ELF loader + instruction patcher (literal-pool aware)
  trap.rs         SIGILL handler; instruction emulation + dispatch
  decoder.rs      decode helpers (generated table from data/encoding/)
  syscall.rs      Linux syscall dispatch and translation
  signal.rs       guest signal forwarding; sigframe build/restore
  thread.rs       fork/clone trampolines, wait4, futex
  trampoline.rs   post-signal trampoline pages (fork, mprotect)
  x18_trampoline.rs  x18 virtualization
  net.rs          sockets / networking translation
  procfs.rs       synthetic /proc, /sys
  rootfs.rs       path rebasing into the guest rootfs
  pidns.rs        virtual PID namespace
  creds.rs        virtual uid/gid (unshare -r semantics)
  ...
build.rs          parses ARM A64 ISA XML → generates the decode table
data/encoding/    ARM A64 ISA spec (only needed to regenerate the decoder)
roots/            guest root filesystems (fetched on demand; gitignored)
scripts/          helper scripts (fetch-rootfs.sh, fetch-arm-isa-xml.sh, …)
tests/            C integration tests + run_tests.sh
docs/             design notes, roadmap, known issues
docs/devlog/      development journal (the messy, honest story)
```

## Documentation

- [`docs/theory.md`](docs/theory.md) — fork concurrency & the trampoline pattern.
- [`docs/compatibility-roadmap.md`](docs/compatibility-roadmap.md) — path toward broader Linux compatibility.
- [`docs/known-issues.md`](docs/known-issues.md) — current limitations.
- [`docs/devlog/`](docs/devlog/) — chronological development diary; the source of
  most of the hard-won Apple-Silicon trivia in this project.

## License

MIT — see [`LICENSE`](LICENSE).

The contents of `data/encoding/` are derived from ARM's published Architecture
Specification and are subject to ARM's own licensing terms; see
[`data/encoding/README.md`](data/encoding/README.md).
