// Test /proc/cpuinfo virtual file
#include <fcntl.h>
#include <unistd.h>

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

// Simple substring search
static int contains(const char *haystack, int haystack_len, const char *needle) {
    int nlen = 0;
    while (needle[nlen]) nlen++;
    for (int i = 0; i <= haystack_len - nlen; i++) {
        int match = 1;
        for (int j = 0; j < nlen; j++) {
            if (haystack[i+j] != needle[j]) { match = 0; break; }
        }
        if (match) return 1;
    }
    return 0;
}

int main(void) {
    int fd;
    long ret;

    // Test 1: /proc/cpuinfo
    fd = my_open("/proc/cpuinfo", 0x0); // O_RDONLY
    if (fd < 0) {
        print("FAIL: cannot open /proc/cpuinfo\n");
        my_exit(1);
    }

    char buf[4096];
    long total = 0;
    while ((ret = my_read(fd, buf + total, sizeof(buf) - total - 1)) > 0) {
        total += ret;
    }
    my_close(fd);
    buf[total] = 0;

    if (total <= 0) {
        print("FAIL: /proc/cpuinfo is empty\n");
        my_exit(1);
    }

    if (!contains(buf, total, "processor")) {
        print("FAIL: /proc/cpuinfo missing 'processor'\n");
        my_exit(1);
    }

    if (!contains(buf, total, "Features")) {
        print("FAIL: /proc/cpuinfo missing 'Features'\n");
        my_exit(1);
    }

    print("PASS: /proc/cpuinfo OK\n");

    // Test 2: /proc/sys/kernel/osrelease
    fd = my_open("/proc/sys/kernel/osrelease", 0x0);
    if (fd < 0) {
        print("FAIL: cannot open /proc/sys/kernel/osrelease\n");
        my_exit(1);
    }

    total = 0;
    while ((ret = my_read(fd, buf + total, sizeof(buf) - total - 1)) > 0) {
        total += ret;
    }
    my_close(fd);
    buf[total] = 0;

    if (!contains(buf, total, "fakelinux")) {
        print("FAIL: osrelease missing 'fakelinux'\n");
        my_exit(1);
    }
    print("PASS: /proc/sys/kernel/osrelease OK\n");

    // Test 3: /proc/meminfo
    fd = my_open("/proc/meminfo", 0x0);
    if (fd < 0) {
        print("FAIL: cannot open /proc/meminfo\n");
        my_exit(1);
    }

    total = 0;
    while ((ret = my_read(fd, buf + total, sizeof(buf) - total - 1)) > 0) {
        total += ret;
    }
    my_close(fd);
    buf[total] = 0;

    if (!contains(buf, total, "MemTotal")) {
        print("FAIL: /proc/meminfo missing 'MemTotal'\n");
        my_exit(1);
    }
    print("PASS: /proc/meminfo OK\n");

    print("ALL PASS\n");
    my_exit(0);
}
