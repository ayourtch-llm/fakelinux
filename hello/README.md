# hello/ — smoke-test binaries

Small "hello world" aarch64 Linux programs used to exercise fakelinux's ELF
loader and basic syscall path across libc/link-mode variants. They are handy
first targets when bringing up or debugging the emulator:

```sh
cargo build --release
./hello/build.sh                              # build the binaries (see below)
./target/release/fakelinux ./hello/hello_static_pie
```

The compiled binaries are **gitignored** (only this directory's sources are
tracked: `hello.c`, `build.sh`, this README).

## Building

```sh
./hello/build.sh
```

produces, in this directory:

- `hello_min` — minimal hand-emitted static ELF, via `cargo run --bin gen_test_elf`
  (no cross-compiler needed).
- `hello_musl`, `hello_musl_pie` — musl, static / static-PIE (Alpine arm64).
- `hello_dynamic`, `hello_static_pie` — glibc, dynamic / static-PIE (Debian arm64).

The libc-linked variants are cross-compiled in Docker (`--platform linux/arm64`),
the same approach as `tests/run_tests.sh`. If Docker isn't available, only
`hello_min` is built.
