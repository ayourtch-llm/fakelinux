#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>

/* Linux aarch64 syscall numbers */
#define __NR_eventfd2  19
#define __NR_ppoll     73

/* Linux pollfd */
struct linux_pollfd {
    int fd;
    short events;
    short revents;
};

#define LINUX_POLLIN 0x0001

struct linux_timespec {
    long tv_sec;
    long tv_nsec;
};

int main(void) {
    int efd;
    long ret;
    unsigned long long val;

    printf("TEST: eventfd2 syscall (nr 19)\n");

    /* Create eventfd with initial value 0, no flags */
    efd = (int)syscall(__NR_eventfd2, 0, 0);
    if (efd < 0) {
        printf("FAIL: eventfd2 returned %d\n", efd);
        return 1;
    }
    printf("  eventfd2: fd=%d (OK)\n", efd);

    /* Write value 5 */
    val = 5;
    ret = write(efd, &val, sizeof(val));
    if (ret != 8) {
        printf("FAIL: write(5) returned %ld (expected 8)\n", ret);
        return 1;
    }
    printf("  write(5): OK\n");

    /* Write value 3 (should accumulate: 5+3=8) */
    val = 3;
    ret = write(efd, &val, sizeof(val));
    if (ret != 8) {
        printf("FAIL: write(3) returned %ld (expected 8)\n", ret);
        return 1;
    }
    printf("  write(3): OK\n");

    /* Read from eventfd - should return 8 and reset counter to 0 */
    val = 0;
    ret = read(efd, &val, sizeof(val));
    if (ret != 8) {
        printf("FAIL: read returned %ld (expected 8)\n", ret);
        return 1;
    }
    if (val != 8) {
        printf("FAIL: read value=%llu (expected 8)\n", val);
        return 1;
    }
    printf("  read: value=%llu (OK)\n", val);

    /* Poll eventfd after read - should NOT be readable (counter is 0) */
    struct linux_pollfd fds;
    fds.fd = efd;
    fds.events = LINUX_POLLIN;
    fds.revents = 0;

    struct linux_timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 50000000; /* 50ms */

    ret = syscall(__NR_ppoll, &fds, 1, &ts, NULL, 0);
    if (ret != 0) {
        printf("FAIL: ppoll after read returned %ld (expected 0, counter should be 0)\n", ret);
        return 1;
    }
    printf("  ppoll after read: returned 0 (not readable, OK)\n");

    close(efd);

    printf("PASS: eventfd2 syscall works correctly\n");
    return 0;
}
