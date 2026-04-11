#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <fcntl.h>

/* Linux aarch64 syscall numbers */
#define __NR_pread64  67
#define __NR_pwrite64 68

int main(void) {
    int fd;
    long ret;
    char buf[16] = {0};
    off_t pos;

    printf("TEST: pread64/pwrite64 syscalls (nr 67/68)\n");

    /* Open a temp file */
    fd = open("/tmp/test_pread_tmp", O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        printf("FAIL: open() failed\n");
        return 1;
    }

    /* Use pwrite64 to write "ABCDE" at offset 10 */
    ret = syscall(__NR_pwrite64, fd, "ABCDE", 5, (long long)10);
    if (ret != 5) {
        printf("FAIL: pwrite64 returned %ld, expected 5\n", ret);
        unlink("/tmp/test_pread_tmp");
        return 1;
    }
    printf("  pwrite64 wrote %ld bytes at offset 10 (OK)\n", ret);

    /* Check that file position was NOT changed by pwrite64 */
    pos = lseek(fd, 0, SEEK_CUR);
    if (pos != 0) {
        printf("FAIL: file position after pwrite64 is %ld, expected 0\n", (long)pos);
        unlink("/tmp/test_pread_tmp");
        return 1;
    }
    printf("  file position after pwrite64 = %ld (unchanged, OK)\n", (long)pos);

    /* Use pread64 to read back from offset 10 */
    memset(buf, 0, sizeof(buf));
    ret = syscall(__NR_pread64, fd, buf, 5, (long long)10);
    if (ret != 5) {
        printf("FAIL: pread64 returned %ld, expected 5\n", ret);
        unlink("/tmp/test_pread_tmp");
        return 1;
    }
    printf("  pread64 read %ld bytes from offset 10 (OK)\n", ret);

    /* Verify data matches */
    if (memcmp(buf, "ABCDE", 5) != 0) {
        printf("FAIL: pread64 data = \"%.5s\", expected \"ABCDE\"\n", buf);
        unlink("/tmp/test_pread_tmp");
        return 1;
    }
    printf("  pread64 data = \"%.5s\" (matches, OK)\n", buf);

    /* Check that file position was NOT changed by pread64 */
    pos = lseek(fd, 0, SEEK_CUR);
    if (pos != 0) {
        printf("FAIL: file position after pread64 is %ld, expected 0\n", (long)pos);
        unlink("/tmp/test_pread_tmp");
        return 1;
    }
    printf("  file position after pread64 = %ld (unchanged, OK)\n", (long)pos);

    /* Verify the file has the right content: 10 zero bytes + "ABCDE" */
    lseek(fd, 0, SEEK_SET);
    memset(buf, 0xFF, sizeof(buf));
    ret = read(fd, buf, 15);
    if (ret != 15) {
        printf("FAIL: full read returned %ld, expected 15\n", ret);
        unlink("/tmp/test_pread_tmp");
        return 1;
    }
    /* First 10 bytes should be zero (sparse file / hole) */
    int i;
    for (i = 0; i < 10; i++) {
        if (buf[i] != 0) {
            printf("FAIL: byte %d = 0x%02x, expected 0x00\n", i, (unsigned char)buf[i]);
            unlink("/tmp/test_pread_tmp");
            return 1;
        }
    }
    if (memcmp(buf + 10, "ABCDE", 5) != 0) {
        printf("FAIL: bytes 10-14 don't match \"ABCDE\"\n");
        unlink("/tmp/test_pread_tmp");
        return 1;
    }
    printf("  full file content verified (10 zero bytes + \"ABCDE\", OK)\n");

    close(fd);
    unlink("/tmp/test_pread_tmp");

    printf("PASS: pread64/pwrite64 syscalls work correctly\n");
    return 0;
}
