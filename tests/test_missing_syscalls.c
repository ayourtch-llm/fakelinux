// Test: sendfile, setgid, setuid syscalls
// These show up as unimplemented when running Alpine rootfs.
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

// Test setgid (syscall 144): should succeed when setting to current gid
static void test_setgid(void) {
    long gid = syscall(SYS_getgid);
    long ret = syscall(144, gid);  // setgid to current gid
    check("setgid(current_gid) returns 0", ret == 0);
}

// Test setuid (syscall 146): should succeed when setting to current uid
static void test_setuid(void) {
    long uid = syscall(SYS_getuid);
    long ret = syscall(146, uid);  // setuid to current uid
    check("setuid(current_uid) returns 0", ret == 0);
}

// Test sendfile (syscall 71): copy data between file descriptors
static void test_sendfile(void) {
    // Create a pipe to write sendfile output into
    int pipefd[2];
    if (syscall(SYS_pipe2, pipefd, 0) < 0) {
        check("sendfile: pipe2 failed", 0);
        return;
    }

    // Open /proc/self/maps as a readable source file (always exists)
    int src_fd = syscall(SYS_openat, -100, "/proc/self/maps", 0 /*O_RDONLY*/, 0);
    if (src_fd < 0) {
        // Try /dev/null as fallback - just test that the syscall doesn't ENOSYS
        src_fd = syscall(SYS_openat, -100, "/dev/null", 0, 0);
        if (src_fd < 0) {
            check("sendfile: cannot open source file", 0);
            syscall(SYS_close, pipefd[0]);
            syscall(SYS_close, pipefd[1]);
            return;
        }
    }

    // sendfile(out_fd, in_fd, offset_ptr, count)
    long ret = syscall(71, pipefd[1], src_fd, 0 /*NULL offset*/, 4096);
    // ret >= 0 means success (could be 0 if source is empty like /dev/null)
    check("sendfile returns >= 0", ret >= 0);

    syscall(SYS_close, src_fd);
    syscall(SYS_close, pipefd[0]);
    syscall(SYS_close, pipefd[1]);
}

int main(void) {
    test_setgid();
    test_setuid();
    test_sendfile();

    if (tests_passed == tests_run) {
        const char msg[] = "PASS: all missing syscall tests passed\n";
        write(1, msg, sizeof(msg) - 1);
        return 0;
    } else {
        char buf[64];
        int i = 0;
        const char *p = "FAIL: ";
        while (*p) buf[i++] = *p++;
        buf[i++] = '0' + (tests_passed % 10);
        buf[i++] = '/';
        buf[i++] = '0' + (tests_run % 10);
        p = " tests passed\n";
        while (*p) buf[i++] = *p++;
        write(1, buf, i);
        return 1;
    }
}
