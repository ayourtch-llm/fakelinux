#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <fcntl.h>

/* Linux aarch64 syscall number for statx */
#define __NR_statx 291

/* statx flags */
#define AT_EMPTY_PATH       0x1000
#define STATX_BASIC_STATS   0x07ffU

/* S_IFMT and S_IFDIR from Linux */
#define LINUX_S_IFMT   0170000
#define LINUX_S_IFDIR  0040000

/*
 * Manually define struct statx layout (Linux 4.11+).
 * We don't rely on system headers having it.
 */
struct linux_statx {
    unsigned int stx_mask;
    unsigned int stx_blksize;
    unsigned long long stx_attributes;
    unsigned int stx_nlink;
    unsigned int stx_uid;
    unsigned int stx_gid;
    unsigned short stx_mode;
    unsigned short __spare0[1];
    unsigned long long stx_ino;
    unsigned long long stx_size;
    unsigned long long stx_blocks;
    unsigned long long stx_attributes_mask;
    /* timestamps */
    struct {
        long long tv_sec;
        unsigned int tv_nsec;
        int __reserved;
    } stx_atime, stx_btime, stx_ctime, stx_mtime;
    unsigned int stx_rdev_major;
    unsigned int stx_rdev_minor;
    unsigned int stx_dev_major;
    unsigned int stx_dev_minor;
    unsigned long long stx_mnt_id;
    unsigned long long __spare2;
    unsigned long long __spare3[12];
};

int main(void) {
    struct linux_statx buf;
    long ret;

    printf("TEST: statx syscall (nr 291)\n");

    memset(&buf, 0, sizeof(buf));

    /* statx(AT_FDCWD, ".", 0, STATX_BASIC_STATS, &buf) */
    ret = syscall(__NR_statx, -100 /* AT_FDCWD */, ".", 0, STATX_BASIC_STATS, &buf);

    if (ret != 0) {
        printf("FAIL: statx returned %ld\n", ret);
        return 1;
    }
    printf("  statx returned 0 (OK)\n");

    /* Check that stx_mode has S_IFDIR bit set */
    if ((buf.stx_mode & LINUX_S_IFMT) != LINUX_S_IFDIR) {
        printf("FAIL: stx_mode=0%o, expected directory (S_IFDIR=0%o)\n",
               buf.stx_mode, LINUX_S_IFDIR);
        return 1;
    }
    printf("  stx_mode=0%o (is a directory, OK)\n", buf.stx_mode);

    /* Check stx_blksize > 0 */
    if (buf.stx_blksize == 0) {
        printf("FAIL: stx_blksize is 0\n");
        return 1;
    }
    printf("  stx_blksize=%u (OK)\n", buf.stx_blksize);

    /* Check stx_nlink > 0 (directories have at least 2 links: . and ..) */
    if (buf.stx_nlink == 0) {
        printf("FAIL: stx_nlink is 0\n");
        return 1;
    }
    printf("  stx_nlink=%u (OK)\n", buf.stx_nlink);

    printf("PASS: statx syscall works correctly\n");
    return 0;
}
