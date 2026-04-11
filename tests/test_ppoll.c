#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>

/* Linux aarch64 syscall numbers */
#define __NR_ppoll 73
#define __NR_pipe2 59

/* Linux pollfd structure (same layout on Linux aarch64) */
struct linux_pollfd {
    int fd;
    short events;
    short revents;
};

/* Linux poll event flags */
#define LINUX_POLLIN   0x0001
#define LINUX_POLLOUT  0x0004

/* Linux timespec */
struct linux_timespec {
    long tv_sec;
    long tv_nsec;
};

int main(void) {
    int pipefd[2];
    long ret;

    printf("TEST: ppoll syscall (nr 73)\n");

    /* Create a pipe */
    ret = syscall(__NR_pipe2, pipefd, 0);
    if (ret != 0) {
        printf("FAIL: pipe2 returned %ld\n", ret);
        return 1;
    }
    printf("  pipe created: read_fd=%d, write_fd=%d\n", pipefd[0], pipefd[1]);

    /* Test 1: ppoll on pipe with data - write "hello" first */
    ret = write(pipefd[1], "hello", 5);
    if (ret != 5) {
        printf("FAIL: write returned %ld\n", ret);
        return 1;
    }

    struct linux_pollfd fds;
    fds.fd = pipefd[0];
    fds.events = LINUX_POLLIN;
    fds.revents = 0;

    struct linux_timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 100000000; /* 100ms */

    /* ppoll(fds, nfds, timeout, sigmask, sigsetsize) */
    ret = syscall(__NR_ppoll, &fds, 1, &ts, NULL, 0);
    if (ret != 1) {
        printf("FAIL: ppoll with data returned %ld (expected 1)\n", ret);
        return 1;
    }
    if (!(fds.revents & LINUX_POLLIN)) {
        printf("FAIL: revents=0x%x, expected POLLIN (0x%x)\n", fds.revents, LINUX_POLLIN);
        return 1;
    }
    printf("  ppoll with data: returned %ld, revents=0x%x (POLLIN, OK)\n", ret, fds.revents);

    /* Drain the pipe */
    char buf[16];
    read(pipefd[0], buf, sizeof(buf));

    /* Test 2: ppoll timeout on empty pipe */
    fds.fd = pipefd[0];
    fds.events = LINUX_POLLIN;
    fds.revents = 0;

    ts.tv_sec = 0;
    ts.tv_nsec = 50000000; /* 50ms */

    ret = syscall(__NR_ppoll, &fds, 1, &ts, NULL, 0);
    if (ret != 0) {
        printf("FAIL: ppoll timeout returned %ld (expected 0)\n", ret);
        return 1;
    }
    printf("  ppoll timeout: returned %ld (OK)\n", ret);

    close(pipefd[0]);
    close(pipefd[1]);

    printf("PASS: ppoll syscall works correctly\n");
    return 0;
}
