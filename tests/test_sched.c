#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Linux aarch64 syscall numbers */
#define __NR_sched_getaffinity 123
#define __NR_sched_setaffinity 122

static long my_syscall3(long nr, long a0, long a1, long a2) {
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x8 __asm__("x8") = nr;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
}

int main(void) {
    unsigned long mask = 0;
    long ret;

    printf("TEST: sched_getaffinity/sched_setaffinity\n");

    /* Test 1: sched_getaffinity(0, 8, &mask) — get affinity for current process */
    ret = my_syscall3(__NR_sched_getaffinity, 0, 8, (long)&mask);
    if (ret <= 0) {
        printf("FAIL: sched_getaffinity returned %ld (expected > 0)\n", ret);
        return 1;
    }
    printf("  sched_getaffinity: returned %ld, mask=0x%lx\n", ret, mask);

    /* Check that at least 1 bit is set */
    if (mask == 0) {
        printf("FAIL: affinity mask is empty\n");
        return 1;
    }

    /* Count CPUs */
    int ncpu = 0;
    unsigned long m = mask;
    while (m) {
        ncpu += m & 1;
        m >>= 1;
    }
    printf("  CPUs in affinity mask: %d\n", ncpu);

    /* Test 2: sched_setaffinity(0, 8, &mask) — set affinity (stub) */
    ret = my_syscall3(__NR_sched_setaffinity, 0, 8, (long)&mask);
    if (ret != 0) {
        printf("FAIL: sched_setaffinity returned %ld (expected 0)\n", ret);
        return 1;
    }
    printf("  sched_setaffinity: returned %ld (OK)\n", ret);

    printf("PASS: sched_getaffinity/sched_setaffinity work correctly\n");
    return 0;
}
