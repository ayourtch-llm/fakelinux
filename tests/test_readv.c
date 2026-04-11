#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>

/* Linux aarch64 syscall number for readv */
#define __NR_readv 65

struct iovec {
    void  *iov_base;
    unsigned long iov_len;
};

int main(void) {
    int pipefd[2];
    char buf1[5] = {0};
    char buf2[5] = {0};
    struct iovec iov[2];
    long ret;

    printf("TEST: readv syscall (nr 65)\n");

    /* Create a pipe */
    if (pipe(pipefd) != 0) {
        printf("FAIL: pipe() failed\n");
        return 1;
    }

    /* Write known data to the pipe */
    const char *data = "HelloWorld";
    if (write(pipefd[1], data, 10) != 10) {
        printf("FAIL: write() to pipe failed\n");
        return 1;
    }
    close(pipefd[1]);

    /* Set up two iovecs: 5 bytes each */
    iov[0].iov_base = buf1;
    iov[0].iov_len = 5;
    iov[1].iov_base = buf2;
    iov[1].iov_len = 5;

    /* Use raw syscall for readv */
    ret = syscall(__NR_readv, pipefd[0], iov, 2);

    if (ret != 10) {
        printf("FAIL: readv returned %ld, expected 10\n", ret);
        return 1;
    }
    printf("  readv returned %ld bytes (OK)\n", ret);

    /* Verify first iovec got "Hello" */
    if (memcmp(buf1, "Hello", 5) != 0) {
        printf("FAIL: buf1 = \"%.5s\", expected \"Hello\"\n", buf1);
        return 1;
    }
    printf("  buf1 = \"%.5s\" (OK)\n", buf1);

    /* Verify second iovec got "World" */
    if (memcmp(buf2, "World", 5) != 0) {
        printf("FAIL: buf2 = \"%.5s\", expected \"World\"\n", buf2);
        return 1;
    }
    printf("  buf2 = \"%.5s\" (OK)\n", buf2);

    close(pipefd[0]);

    printf("PASS: readv syscall works correctly\n");
    return 0;
}
