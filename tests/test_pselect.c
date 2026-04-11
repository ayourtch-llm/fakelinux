#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

/* Linux aarch64 syscall numbers */
#define __NR_pselect6 72
#define __NR_pipe2 59

/* fd_set is 128 bytes on Linux aarch64 (1024 bits) */
typedef struct {
    unsigned long fds_bits[1024 / (8 * sizeof(unsigned long))];
} linux_fd_set;

#define LINUX_FD_ZERO(set) memset((set), 0, sizeof(linux_fd_set))
#define LINUX_FD_SET(fd, set) ((set)->fds_bits[(fd) / (8 * sizeof(unsigned long))] |= (1UL << ((fd) % (8 * sizeof(unsigned long)))))
#define LINUX_FD_ISSET(fd, set) (((set)->fds_bits[(fd) / (8 * sizeof(unsigned long))] >> ((fd) % (8 * sizeof(unsigned long)))) & 1)

struct linux_timespec {
    long tv_sec;
    long tv_nsec;
};

static long my_syscall6(long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    register long x8 __asm__("x8") = nr;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8) : "memory");
    return x0;
}

int main(void) {
    int pipefd[2];
    long ret;

    printf("TEST: pselect6 syscall (nr 72)\n");

    /* Create a pipe */
    ret = my_syscall6(__NR_pipe2, (long)pipefd, 0, 0, 0, 0, 0);
    if (ret != 0) {
        printf("FAIL: pipe2 returned %ld\n", ret);
        return 1;
    }
    printf("  pipe created: read_fd=%d, write_fd=%d\n", pipefd[0], pipefd[1]);

    /* Test 1: pselect on pipe with data */
    ret = write(pipefd[1], "hello", 5);
    if (ret != 5) {
        printf("FAIL: write returned %ld\n", ret);
        return 1;
    }

    linux_fd_set readfds;
    LINUX_FD_ZERO(&readfds);
    LINUX_FD_SET(pipefd[0], &readfds);

    struct linux_timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 100000000; /* 100ms */

    int nfds = pipefd[0] + 1;

    /* pselect6(nfds, readfds, writefds, exceptfds, timeout, sigmask_struct) */
    ret = my_syscall6(__NR_pselect6, nfds, (long)&readfds, 0, 0, (long)&ts, 0);
    if (ret != 1) {
        printf("FAIL: pselect6 with data returned %ld (expected 1)\n", ret);
        return 1;
    }
    if (!LINUX_FD_ISSET(pipefd[0], &readfds)) {
        printf("FAIL: pselect6 did not set read fd in readfds\n");
        return 1;
    }
    printf("  pselect6 with data: returned %ld, fd is readable (OK)\n", ret);

    /* Drain the pipe */
    char buf[16];
    read(pipefd[0], buf, sizeof(buf));

    /* Test 2: pselect6 timeout on empty pipe */
    LINUX_FD_ZERO(&readfds);
    LINUX_FD_SET(pipefd[0], &readfds);

    ts.tv_sec = 0;
    ts.tv_nsec = 50000000; /* 50ms */

    ret = my_syscall6(__NR_pselect6, nfds, (long)&readfds, 0, 0, (long)&ts, 0);
    if (ret != 0) {
        printf("FAIL: pselect6 timeout returned %ld (expected 0)\n", ret);
        return 1;
    }
    printf("  pselect6 timeout: returned %ld (OK)\n", ret);

    close(pipefd[0]);
    close(pipefd[1]);

    printf("PASS: pselect6 syscall works correctly\n");
    return 0;
}
