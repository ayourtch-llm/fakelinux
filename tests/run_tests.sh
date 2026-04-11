#!/bin/bash
# Test harness: cross-compile C test files in Docker (linux/arm64 alpine)
# and run each under fakelinux, checking exit codes and stdout.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
FAKELINUX="$PROJECT_DIR/target/debug/fakelinux"

# Build fakelinux first
echo "=== Building fakelinux ==="
(cd "$PROJECT_DIR" && cargo build)

# Collect all test source files
TEST_SOURCES=("$SCRIPT_DIR"/test_*.c)
if [ ${#TEST_SOURCES[@]} -eq 0 ]; then
    echo "No test files found in $SCRIPT_DIR"
    exit 1
fi

# Cross-compile all tests in Docker
echo "=== Cross-compiling tests in Docker ==="
docker run --rm --platform linux/arm64 \
    -v "$SCRIPT_DIR:/tests" \
    alpine:latest \
    sh -c '
        apk add --no-cache gcc musl-dev >/dev/null 2>&1
        for src in /tests/test_*.c; do
            base=$(basename "$src" .c)
            echo "  Compiling $base..."
            gcc -static-pie -o "/tests/$base" "$src" || exit 1
        done
    '

# Run each test under fakelinux
PASSED=0
FAILED=0
ERRORS=""

for src in "${TEST_SOURCES[@]}"; do
    base=$(basename "$src" .c)
    binary="$SCRIPT_DIR/$base"

    if [ ! -f "$binary" ]; then
        echo "SKIP $base (binary not found)"
        continue
    fi

    echo "--- Running $base ---"
    if output=$("$FAKELINUX" "$binary" 2>&1); then
        echo "$output"
        echo "PASS $base"
        PASSED=$((PASSED + 1))
    else
        echo "$output"
        echo "FAIL $base (exit code $?)"
        FAILED=$((FAILED + 1))
        ERRORS="$ERRORS  $base\n"
    fi
    echo
done

# Clean up compiled binaries
for src in "${TEST_SOURCES[@]}"; do
    base=$(basename "$src" .c)
    rm -f "$SCRIPT_DIR/$base"
done

echo "=== Results: $PASSED passed, $FAILED failed ==="
if [ $FAILED -gt 0 ]; then
    echo -e "Failed tests:\n$ERRORS"
    exit 1
fi
