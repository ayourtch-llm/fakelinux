#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Linux aarch64 syscall numbers */
#define __NR_prctl 167

/* prctl options */
#define PR_SET_NAME 15
#define PR_GET_NAME 16

static long my_syscall5(long nr, long a0, long a1, long a2, long a3, long a4) {
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x8 __asm__("x8") = nr;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8) : "memory");
    return x0;
}

int main(void) {
    long ret;

    printf("TEST: prctl syscall (nr 167)\n");

    /* Test 1: PR_SET_NAME */
    ret = my_syscall5(__NR_prctl, PR_SET_NAME, (long)"testname", 0, 0, 0);
    if (ret != 0) {
        printf("FAIL: prctl(PR_SET_NAME) returned %ld (expected 0)\n", ret);
        return 1;
    }
    printf("  prctl(PR_SET_NAME, \"testname\"): returned %ld (OK)\n", ret);

    /* Test 2: PR_GET_NAME */
    char name[16];
    memset(name, 0, sizeof(name));
    ret = my_syscall5(__NR_prctl, PR_GET_NAME, (long)name, 0, 0, 0);
    if (ret != 0) {
        printf("FAIL: prctl(PR_GET_NAME) returned %ld (expected 0)\n", ret);
        return 1;
    }
    printf("  prctl(PR_GET_NAME): returned %ld, name=\"%s\" (OK)\n", ret, name);

    printf("PASS: prctl syscall works correctly\n");
    return 0;
}
