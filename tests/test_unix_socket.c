#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

/*
 * Unix socket test: socketpair + read/write.
 */

int main(void) {
    int sv[2];

    printf("TEST: Unix domain socketpair\n");

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        printf("FAIL: socketpair() failed\n");
        return 1;
    }
    printf("  socketpair: fd[0]=%d fd[1]=%d\n", sv[0], sv[1]);

    const char *msg = "UNIX";
    if (write(sv[0], msg, 4) != 4) {
        printf("FAIL: write to sv[0] failed\n");
        return 1;
    }

    char buf[16];
    ssize_t n = read(sv[1], buf, sizeof(buf));
    if (n != 4 || memcmp(buf, "UNIX", 4) != 0) {
        printf("FAIL: read from sv[1] got %zd bytes\n", n);
        return 1;
    }
    printf("  read from sv[1]: '%.*s'\n", (int)n, buf);

    /* Test the other direction */
    const char *msg2 = "BACK";
    if (write(sv[1], msg2, 4) != 4) {
        printf("FAIL: write to sv[1] failed\n");
        return 1;
    }

    n = read(sv[0], buf, sizeof(buf));
    if (n != 4 || memcmp(buf, "BACK", 4) != 0) {
        printf("FAIL: read from sv[0] got %zd bytes\n", n);
        return 1;
    }
    printf("  read from sv[0]: '%.*s'\n", (int)n, buf);

    close(sv[0]);
    close(sv[1]);

    printf("PASS: Unix domain socketpair works correctly\n");
    return 0;
}
