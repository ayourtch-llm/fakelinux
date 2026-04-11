// Test /dev/null, /dev/zero, /dev/urandom passthrough
#include <fcntl.h>
#include <unistd.h>

// Inline syscall helper for aarch64 Linux
static long my_syscall3(long nr, long a0, long a1, long a2) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}

static long my_syscall4(long nr, long a0, long a1, long a2, long a3) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory");
    return x0;
}

#define SYS_openat 56
#define SYS_read   63
#define SYS_write  64
#define SYS_close  57
#define SYS_exit_group 94
#define AT_FDCWD (-100)

static void my_exit(int code) {
    my_syscall3(SYS_exit_group, code, 0, 0);
    __builtin_unreachable();
}

static int my_open(const char *path, int flags) {
    return (int)my_syscall4(SYS_openat, AT_FDCWD, (long)path, flags, 0);
}

static long my_read(int fd, void *buf, long count) {
    return my_syscall3(SYS_read, fd, (long)buf, count);
}

static long my_write(int fd, const void *buf, long count) {
    return my_syscall3(SYS_write, fd, (long)buf, count);
}

static void my_close(int fd) {
    my_syscall3(SYS_close, fd, 0, 0);
}

static void print(const char *msg) {
    int len = 0;
    while (msg[len]) len++;
    my_write(1, msg, len);
}

int main(void) {
    int fd;
    long ret;

    // Test 1: /dev/null - write should succeed
    fd = my_open("/dev/null", 0x1); // O_WRONLY
    if (fd < 0) {
        print("FAIL: cannot open /dev/null\n");
        my_exit(1);
    }
    ret = my_write(fd, "test", 4);
    my_close(fd);
    if (ret != 4) {
        print("FAIL: write to /dev/null returned wrong count\n");
        my_exit(1);
    }
    print("PASS: /dev/null write OK\n");

    // Test 2: /dev/zero - read should return all zeros
    fd = my_open("/dev/zero", 0x0); // O_RDONLY
    if (fd < 0) {
        print("FAIL: cannot open /dev/zero\n");
        my_exit(1);
    }
    unsigned char zbuf[4] = {0xff, 0xff, 0xff, 0xff};
    ret = my_read(fd, zbuf, 4);
    my_close(fd);
    if (ret != 4) {
        print("FAIL: read from /dev/zero returned wrong count\n");
        my_exit(1);
    }
    if (zbuf[0] != 0 || zbuf[1] != 0 || zbuf[2] != 0 || zbuf[3] != 0) {
        print("FAIL: /dev/zero returned non-zero data\n");
        my_exit(1);
    }
    print("PASS: /dev/zero read OK\n");

    // Test 3: /dev/urandom - read should return data (not all zeros)
    fd = my_open("/dev/urandom", 0x0); // O_RDONLY
    if (fd < 0) {
        print("FAIL: cannot open /dev/urandom\n");
        my_exit(1);
    }
    unsigned char rbuf[8] = {0};
    ret = my_read(fd, rbuf, 8);
    my_close(fd);
    if (ret != 8) {
        print("FAIL: read from /dev/urandom returned wrong count\n");
        my_exit(1);
    }
    // Check that at least one byte is non-zero (probability of all zeros ~= 0)
    int all_zero = 1;
    for (int i = 0; i < 8; i++) {
        if (rbuf[i] != 0) { all_zero = 0; break; }
    }
    if (all_zero) {
        print("FAIL: /dev/urandom returned all zeros\n");
        my_exit(1);
    }
    print("PASS: /dev/urandom read OK\n");

    print("ALL PASS\n");
    my_exit(0);
}
