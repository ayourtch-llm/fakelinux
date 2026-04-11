// Test: symlinkat, linkat, flock, utimensat, ftruncate
// These are needed by apk, tar, and common build tools.
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

static void check(const char *name, int ok) {
    tests_run++;
    if (ok) {
        tests_passed++;
    } else {
        write(1, "  FAIL: ", 8);
        write(1, name, strlen(name));
        write(1, "\n", 1);
    }
}

// aarch64 syscall numbers
#define AT_FDCWD -100
#define SYS_SYMLINKAT   36
#define SYS_LINKAT      37
#define SYS_FTRUNCATE   46
#define SYS_FLOCK_NR    32
#define SYS_UTIMENSAT   88

// flock constants
#define LOCK_SH 1
#define LOCK_EX 2
#define LOCK_UN 8
#define LOCK_NB 4

// utimensat constants
#define UTIME_NOW  ((1l << 30) - 1l)
#define UTIME_OMIT ((1l << 30) - 2l)

struct linux_timespec {
    long tv_sec;
    long tv_nsec;
};

static void test_symlinkat(void) {
    // Create a temp file to symlink to
    const char *target = "/tmp/fakelinux_test_symlink_target";
    const char *link_path = "/tmp/fakelinux_test_symlink_link";

    // Create target file
    int fd = syscall(SYS_openat, AT_FDCWD, target, 0102 /*O_CREAT|O_RDWR*/, 0644);
    if (fd < 0) {
        check("symlinkat: create target", 0);
        return;
    }
    syscall(SYS_write, fd, "hello", 5);
    syscall(SYS_close, fd);

    // Remove old link if exists
    syscall(SYS_unlinkat, AT_FDCWD, link_path, 0);

    // Create symlink
    long ret = syscall(SYS_SYMLINKAT, target, AT_FDCWD, link_path);
    check("symlinkat returns 0", ret == 0);

    // Read through symlink
    fd = syscall(SYS_openat, AT_FDCWD, link_path, 0 /*O_RDONLY*/, 0);
    check("open symlink works", fd >= 0);
    if (fd >= 0) {
        char buf[16] = {0};
        long n = syscall(SYS_read, fd, buf, 16);
        check("read through symlink", n == 5 && buf[0] == 'h');
        syscall(SYS_close, fd);
    }

    // Readlink
    char linkbuf[256] = {0};
    long n = syscall(SYS_readlinkat, AT_FDCWD, link_path, linkbuf, 256);
    check("readlinkat returns target", n > 0 && strcmp(linkbuf, target) == 0);

    // Cleanup
    syscall(SYS_unlinkat, AT_FDCWD, link_path, 0);
    syscall(SYS_unlinkat, AT_FDCWD, target, 0);
}

static void test_linkat(void) {
    const char *orig = "/tmp/fakelinux_test_link_orig";
    const char *link = "/tmp/fakelinux_test_link_hard";

    // Create original file
    int fd = syscall(SYS_openat, AT_FDCWD, orig, 0102 /*O_CREAT|O_RDWR*/, 0644);
    if (fd < 0) {
        check("linkat: create orig", 0);
        return;
    }
    syscall(SYS_write, fd, "link test", 9);
    syscall(SYS_close, fd);

    // Remove old hard link if exists
    syscall(SYS_unlinkat, AT_FDCWD, link, 0);

    // Create hard link
    long ret = syscall(SYS_LINKAT, AT_FDCWD, orig, AT_FDCWD, link, 0);
    check("linkat returns 0", ret == 0);

    // Read through hard link
    fd = syscall(SYS_openat, AT_FDCWD, link, 0 /*O_RDONLY*/, 0);
    check("open hard link works", fd >= 0);
    if (fd >= 0) {
        char buf[16] = {0};
        long n = syscall(SYS_read, fd, buf, 16);
        check("read through hard link", n == 9 && buf[0] == 'l');
        syscall(SYS_close, fd);
    }

    // Cleanup
    syscall(SYS_unlinkat, AT_FDCWD, link, 0);
    syscall(SYS_unlinkat, AT_FDCWD, orig, 0);
}

static void test_flock(void) {
    const char *path = "/tmp/fakelinux_test_flock";

    int fd = syscall(SYS_openat, AT_FDCWD, path, 0102 /*O_CREAT|O_RDWR*/, 0644);
    if (fd < 0) {
        check("flock: create file", 0);
        return;
    }

    // Lock exclusive
    long ret = syscall(SYS_FLOCK_NR, fd, LOCK_EX);
    check("flock LOCK_EX returns 0", ret == 0);

    // Unlock
    ret = syscall(SYS_FLOCK_NR, fd, LOCK_UN);
    check("flock LOCK_UN returns 0", ret == 0);

    // Lock shared
    ret = syscall(SYS_FLOCK_NR, fd, LOCK_SH);
    check("flock LOCK_SH returns 0", ret == 0);

    // Unlock
    ret = syscall(SYS_FLOCK_NR, fd, LOCK_UN);
    check("flock LOCK_UN (2) returns 0", ret == 0);

    syscall(SYS_close, fd);
    syscall(SYS_unlinkat, AT_FDCWD, path, 0);
}

static void test_utimensat(void) {
    const char *path = "/tmp/fakelinux_test_utimens";

    int fd = syscall(SYS_openat, AT_FDCWD, path, 0102 /*O_CREAT|O_RDWR*/, 0644);
    if (fd < 0) {
        check("utimensat: create file", 0);
        return;
    }
    syscall(SYS_close, fd);

    // Set both times to specific values
    struct linux_timespec times[2];
    times[0].tv_sec = 1000000;  // atime
    times[0].tv_nsec = 0;
    times[1].tv_sec = 2000000;  // mtime
    times[1].tv_nsec = 0;

    long ret = syscall(SYS_UTIMENSAT, AT_FDCWD, path, times, 0);
    check("utimensat returns 0", ret == 0);

    // Set times to NOW
    times[0].tv_nsec = UTIME_NOW;
    times[1].tv_nsec = UTIME_NOW;
    ret = syscall(SYS_UTIMENSAT, AT_FDCWD, path, times, 0);
    check("utimensat UTIME_NOW returns 0", ret == 0);

    // NULL times = set both to now
    ret = syscall(SYS_UTIMENSAT, AT_FDCWD, path, 0, 0);
    check("utimensat NULL times returns 0", ret == 0);

    syscall(SYS_unlinkat, AT_FDCWD, path, 0);
}

static void test_ftruncate(void) {
    const char *path = "/tmp/fakelinux_test_ftrunc";

    int fd = syscall(SYS_openat, AT_FDCWD, path, 0102 /*O_CREAT|O_RDWR*/, 0644);
    if (fd < 0) {
        check("ftruncate: create file", 0);
        return;
    }

    // Write some data
    syscall(SYS_write, fd, "hello world!", 12);

    // Truncate to 5 bytes
    long ret = syscall(SYS_ftruncate, fd, 5);
    check("ftruncate returns 0", ret == 0);

    // Verify size by reading
    syscall(SYS_lseek, fd, 0, 0 /*SEEK_SET*/);
    char buf[16] = {0};
    long n = syscall(SYS_read, fd, buf, 16);
    check("ftruncate truncated to 5 bytes", n == 5 && buf[4] == 'o');

    // Extend to 20 bytes (zero-fill)
    ret = syscall(SYS_ftruncate, fd, 20);
    check("ftruncate extend returns 0", ret == 0);

    syscall(SYS_lseek, fd, 0, 0);
    n = syscall(SYS_read, fd, buf, 16);
    check("ftruncate extended file readable", n == 16);

    syscall(SYS_close, fd);
    syscall(SYS_unlinkat, AT_FDCWD, path, 0);
}

int main(void) {
    test_symlinkat();
    test_linkat();
    test_flock();
    test_utimensat();
    test_ftruncate();

    char buf[80];
    int i = 0;
    if (tests_passed == tests_run) {
        const char *p = "PASS: all file ops tests passed (";
        while (*p) buf[i++] = *p++;
    } else {
        const char *p = "FAIL: file ops tests (";
        while (*p) buf[i++] = *p++;
    }
    if (tests_passed >= 10) buf[i++] = '0' + (tests_passed / 10);
    buf[i++] = '0' + (tests_passed % 10);
    buf[i++] = '/';
    if (tests_run >= 10) buf[i++] = '0' + (tests_run / 10);
    buf[i++] = '0' + (tests_run % 10);
    buf[i++] = ')';
    buf[i++] = '\n';
    write(1, buf, i);

    return (tests_passed == tests_run) ? 0 : 1;
}
