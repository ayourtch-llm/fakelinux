#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>

/* Linux aarch64 syscall numbers */
#define __NR_epoll_create1  20
#define __NR_epoll_ctl      21
#define __NR_epoll_pwait    22
#define __NR_pipe2          59

/* epoll_ctl operations */
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

/* epoll events */
#define EPOLLIN  0x001
#define EPOLLOUT 0x004

/*
 * Linux aarch64 struct epoll_event is packed to 12 bytes:
 *   uint32_t events;    (offset 0)
 *   uint64_t data;      (offset 4)
 */
struct linux_epoll_event {
    unsigned int events;
    unsigned long long data;
} __attribute__((packed));

int main(void) {
    int epfd, pipefd[2];
    long ret;

    printf("TEST: epoll syscalls (create1/ctl/pwait)\n");

    /* Create epoll instance */
    epfd = (int)syscall(__NR_epoll_create1, 0);
    if (epfd < 0) {
        printf("FAIL: epoll_create1 returned %d\n", epfd);
        return 1;
    }
    printf("  epoll_create1: fd=%d (OK)\n", epfd);

    /* Create a pipe */
    ret = syscall(__NR_pipe2, pipefd, 0);
    if (ret != 0) {
        printf("FAIL: pipe2 returned %ld\n", ret);
        return 1;
    }
    printf("  pipe created: read_fd=%d, write_fd=%d\n", pipefd[0], pipefd[1]);

    /* Add read end to epoll */
    struct linux_epoll_event ev;
    ev.events = EPOLLIN;
    ev.data = (unsigned long long)pipefd[0];

    ret = syscall(__NR_epoll_ctl, epfd, EPOLL_CTL_ADD, pipefd[0], &ev);
    if (ret != 0) {
        printf("FAIL: epoll_ctl ADD returned %ld\n", ret);
        return 1;
    }
    printf("  epoll_ctl ADD: OK\n");

    /* Write data to pipe to make it readable */
    ret = write(pipefd[1], "hello", 5);
    if (ret != 5) {
        printf("FAIL: write returned %ld\n", ret);
        return 1;
    }

    /* epoll_pwait: wait for events */
    struct linux_epoll_event events[4];
    memset(events, 0, sizeof(events));

    /* epoll_pwait(epfd, events, maxevents, timeout_ms, sigmask, sigsetsize) */
    ret = syscall(__NR_epoll_pwait, epfd, events, 4, 100, NULL, 0);
    if (ret != 1) {
        printf("FAIL: epoll_pwait returned %ld (expected 1)\n", ret);
        return 1;
    }
    printf("  epoll_pwait: returned %ld event(s)\n", ret);

    if (!(events[0].events & EPOLLIN)) {
        printf("FAIL: events[0].events=0x%x, expected EPOLLIN\n", events[0].events);
        return 1;
    }
    if (events[0].data != (unsigned long long)pipefd[0]) {
        printf("FAIL: events[0].data=%llu, expected %d\n", events[0].data, pipefd[0]);
        return 1;
    }
    printf("  events[0]: events=0x%x data=%llu (OK)\n", events[0].events, events[0].data);

    /* Test timeout with no events: drain the pipe first */
    char buf[16];
    read(pipefd[0], buf, sizeof(buf));

    /* Remove read end, add it again (test CTL_DEL + CTL_ADD) */
    ret = syscall(__NR_epoll_ctl, epfd, EPOLL_CTL_DEL, pipefd[0], NULL);
    if (ret != 0) {
        printf("FAIL: epoll_ctl DEL returned %ld\n", ret);
        return 1;
    }
    printf("  epoll_ctl DEL: OK\n");

    ev.events = EPOLLIN;
    ev.data = (unsigned long long)pipefd[0];
    ret = syscall(__NR_epoll_ctl, epfd, EPOLL_CTL_ADD, pipefd[0], &ev);
    if (ret != 0) {
        printf("FAIL: epoll_ctl re-ADD returned %ld\n", ret);
        return 1;
    }

    /* epoll_pwait with timeout (50ms), no data available */
    memset(events, 0, sizeof(events));
    ret = syscall(__NR_epoll_pwait, epfd, events, 4, 50, NULL, 0);
    if (ret != 0) {
        printf("FAIL: epoll_pwait timeout returned %ld (expected 0)\n", ret);
        return 1;
    }
    printf("  epoll_pwait timeout: returned 0 (OK)\n");

    close(pipefd[0]);
    close(pipefd[1]);
    close(epfd);

    printf("PASS: epoll syscalls work correctly\n");
    return 0;
}
