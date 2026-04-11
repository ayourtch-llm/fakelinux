/*
 * Test futex WAIT with timeout.
 * Verifies that FUTEX_WAIT returns -ETIMEDOUT after the specified timeout.
 * Also tests FUTEX_WAIT_BITSET (op 9) with a bitset and timeout.
 */
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <time.h>
#include <errno.h>
#include <string.h>

/* Futex operation constants (avoid dependency on linux/futex.h) */
#define FUTEX_WAIT          0
#define FUTEX_WAKE          1
#define FUTEX_WAIT_BITSET   9
#define FUTEX_WAKE_BITSET   10
#define FUTEX_PRIVATE_FLAG  128

static void write_str(const char *s) {
    write(1, s, strlen(s));
}

static void write_num(long n) {
    char buf[32];
    int i = 0;
    if (n < 0) { write(1, "-", 1); n = -n; }
    if (n == 0) { write(1, "0", 1); return; }
    while (n > 0) { buf[i++] = '0' + (n % 10); n /= 10; }
    while (i > 0) { write(1, &buf[--i], 1); }
}

int main(void) {
    int futex_word = 42;
    struct timespec timeout;
    long ret;

    /* Test 1: FUTEX_WAIT with 100ms timeout.
     * The futex value matches (42 == 42), so it should block and then timeout.
     */
    write_str("Test 1: FUTEX_WAIT with 100ms timeout...\n");

    struct timespec before, after;
    clock_gettime(0 /* CLOCK_REALTIME */, &before);

    timeout.tv_sec = 0;
    timeout.tv_nsec = 100000000; /* 100ms */
    ret = syscall(SYS_futex, &futex_word, FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
                  42, &timeout, 0, 0);

    clock_gettime(0, &after);

    long elapsed_ms = (after.tv_sec - before.tv_sec) * 1000 +
                      (after.tv_nsec - before.tv_nsec) / 1000000;

    if (ret != -1 || errno != ETIMEDOUT) {
        write_str("FAIL: expected -ETIMEDOUT, got ret=");
        write_num(ret);
        write_str(" errno=");
        write_num(errno);
        write_str("\n");
        return 1;
    }
    write_str("  returned -ETIMEDOUT (good), elapsed ~");
    write_num(elapsed_ms);
    write_str("ms\n");

    /* Sanity check: elapsed time should be at least 50ms (allowing for timer granularity) */
    if (elapsed_ms < 50) {
        write_str("FAIL: timeout returned too quickly (");
        write_num(elapsed_ms);
        write_str("ms)\n");
        return 1;
    }
    write_str("  PASS\n");

    /* Test 2: FUTEX_WAIT with value mismatch -> immediate EAGAIN */
    write_str("Test 2: FUTEX_WAIT with value mismatch...\n");
    timeout.tv_sec = 10;
    timeout.tv_nsec = 0;
    ret = syscall(SYS_futex, &futex_word, FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
                  999, &timeout, 0, 0);
    if (ret != -1 || errno != EAGAIN) {
        write_str("FAIL: expected -EAGAIN, got ret=");
        write_num(ret);
        write_str(" errno=");
        write_num(errno);
        write_str("\n");
        return 1;
    }
    write_str("  PASS\n");

    /* Test 3: FUTEX_WAIT_BITSET with timeout */
    write_str("Test 3: FUTEX_WAIT_BITSET with 50ms timeout...\n");
    clock_gettime(0, &before);

    timeout.tv_sec = 0;
    timeout.tv_nsec = 50000000; /* 50ms */
    ret = syscall(SYS_futex, &futex_word, FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG,
                  42, &timeout, 0, 0x1);

    clock_gettime(0, &after);
    elapsed_ms = (after.tv_sec - before.tv_sec) * 1000 +
                 (after.tv_nsec - before.tv_nsec) / 1000000;

    if (ret != -1 || errno != ETIMEDOUT) {
        write_str("FAIL: expected -ETIMEDOUT, got ret=");
        write_num(ret);
        write_str(" errno=");
        write_num(errno);
        write_str("\n");
        return 1;
    }
    write_str("  returned -ETIMEDOUT, elapsed ~");
    write_num(elapsed_ms);
    write_str("ms\n");
    write_str("  PASS\n");

    write_str("All futex timeout tests passed!\n");
    return 0;
}
