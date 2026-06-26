#!/usr/bin/env bash
#
# build.sh — build the small "hello world" aarch64 Linux binaries used to
# smoke-test fakelinux's ELF loader and syscall emulation across libc/link-mode
# variants. Outputs land here in hello/ (gitignored).
#
#   ./hello/build.sh
#
# The minimal variant is emitted directly by the gen_test_elf tool (no toolchain
# needed). The libc-linked variants are cross-compiled in Docker (linux/arm64),
# matching the approach used by tests/run_tests.sh.
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"

note() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

# 1. Minimal hand-emitted static ELF — no cross-compiler required.
note "hello_min (gen_test_elf)"
( cd "$REPO" && cargo run --quiet --bin gen_test_elf ) > "$HERE/hello_min"
chmod +x "$HERE/hello_min"

if ! command -v docker >/dev/null 2>&1; then
  note "docker not found — skipping the libc-linked variants (hello_min built)."
  exit 0
fi

# 2. musl variants (Alpine's gcc targets musl).
note "musl variants (Alpine arm64): hello_musl, hello_musl_pie"
docker run --rm --platform linux/arm64 -v "$HERE:/h" alpine:latest sh -c '
  apk add --no-cache gcc musl-dev >/dev/null
  gcc -static     -o /h/hello_musl     /h/hello.c
  gcc -static-pie -o /h/hello_musl_pie /h/hello.c
'

# 3. glibc variants (Debian arm64).
note "glibc variants (Debian arm64): hello_dynamic, hello_static_pie"
docker run --rm --platform linux/arm64 -v "$HERE:/h" debian:stable-slim sh -c '
  apt-get update >/dev/null && apt-get install -y --no-install-recommends gcc libc6-dev >/dev/null
  gcc             -o /h/hello_dynamic    /h/hello.c
  gcc -static-pie -o /h/hello_static_pie /h/hello.c
'

note "done — binaries in hello/ (gitignored). Try: ./target/release/fakelinux ./hello/hello_static_pie"
