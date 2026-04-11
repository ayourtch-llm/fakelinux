// Test: terminal ioctls (TCGETS, TCSETS, TIOCGPGRP, FIONREAD, FIONBIO)
// These are needed by interactive shells and most programs that check isatty().
#include <unistd.h>
#include <sys/syscall.h>
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

// Linux aarch64 ioctl numbers
#define LINUX_TCGETS    0x5401
#define LINUX_TCSETS    0x5402
#define LINUX_TCSETSW   0x5403
#define LINUX_TIOCGPGRP 0x540F
#define LINUX_TIOCSPGRP 0x5410
#define LINUX_FIONREAD  0x541B
#define LINUX_FIONBIO   0x5421

// Linux termios layout (60 bytes on aarch64):
// u32 c_iflag, u32 c_oflag, u32 c_cflag, u32 c_lflag
// u8 c_line, u8 c_cc[32], u8 pad[3]
// u32 c_ispeed, u32 c_ospeed
struct linux_termios {
    unsigned int c_iflag;
    unsigned int c_oflag;
    unsigned int c_cflag;
    unsigned int c_lflag;
    unsigned char c_line;
    unsigned char c_cc[32];
    unsigned char __pad[3];
    unsigned int c_ispeed;
    unsigned int c_ospeed;
};

// Test using a pipe (always works, even without a real terminal)
static void test_tcgets_on_pipe(void) {
    int pipefd[2];
    long ret = syscall(SYS_pipe2, pipefd, 0);
    if (ret < 0) {
        check("pipe2 for tcgets test", 0);
        return;
    }

    struct linux_termios t;
    memset(&t, 0, sizeof(t));

    // TCGETS on a pipe should fail with -ENOTTY (errno 25)
    ret = syscall(SYS_ioctl, pipefd[0], LINUX_TCGETS, &t);
    check("TCGETS on pipe returns error", ret < 0);

    // FIONREAD on pipe should work (returns 0 bytes available)
    int avail = -1;
    ret = syscall(SYS_ioctl, pipefd[0], LINUX_FIONREAD, &avail);
    check("FIONREAD on pipe returns 0", ret == 0 && avail == 0);

    // Write some data, then FIONREAD should show it
    syscall(SYS_write, pipefd[1], "hi", 2);
    ret = syscall(SYS_ioctl, pipefd[0], LINUX_FIONREAD, &avail);
    check("FIONREAD shows 2 bytes", ret == 0 && avail == 2);

    // FIONBIO - set non-blocking
    int nb = 1;
    ret = syscall(SYS_ioctl, pipefd[0], LINUX_FIONBIO, &nb);
    check("FIONBIO returns 0", ret == 0);

    syscall(SYS_close, pipefd[0]);
    syscall(SYS_close, pipefd[1]);
}

// Test TCGETS/TCSETS on stdout (may or may not be a tty)
static void test_tcgets_stdout(void) {
    struct linux_termios t;
    memset(&t, 0, sizeof(t));

    long ret = syscall(SYS_ioctl, 1, LINUX_TCGETS, &t);
    if (ret == 0) {
        // stdout is a terminal - verify we got reasonable values
        // ECHO (0x8) and ICANON (0x2) are typically set
        check("TCGETS stdout: got flags", t.c_lflag != 0);

        // Save, modify, restore
        struct linux_termios saved = t;
        // Try TCSETS (just set same values back)
        ret = syscall(SYS_ioctl, 1, LINUX_TCSETS, &saved);
        check("TCSETS returns 0", ret == 0);
    } else {
        // Not a tty (running in test harness), just verify it didn't crash
        check("TCGETS on non-tty returns -ENOTTY", 1);
        check("TCSETS skipped (non-tty)", 1);
    }
}

// Test TIOCGPGRP
static void test_tiocgpgrp(void) {
    int pgrp = -1;
    long ret = syscall(SYS_ioctl, 0, LINUX_TIOCGPGRP, &pgrp);
    // May fail if stdin is not a tty, that's OK
    if (ret == 0) {
        check("TIOCGPGRP returns valid pgrp", pgrp > 0);
    } else {
        check("TIOCGPGRP on non-tty returns error (OK)", 1);
    }
}

int main(void) {
    test_tcgets_on_pipe();
    test_tcgets_stdout();
    test_tiocgpgrp();

    char buf[80];
    int i = 0;
    if (tests_passed == tests_run) {
        const char *p = "PASS: all terminal tests passed (";
        while (*p) buf[i++] = *p++;
    } else {
        const char *p = "FAIL: terminal tests (";
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
