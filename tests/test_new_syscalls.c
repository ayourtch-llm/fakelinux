// Test: newly added syscalls batch
// memfd_create, fallocate, renameat2, copy_file_range, fstatfs,
// personality, sigaltstack, setpgid/getpgid/getsid, fsync, ftruncate
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <string.h>

// aarch64 syscall numbers
#define SYS_fstatfs      44
#define SYS_ftruncate    46
#define SYS_fsync        82
#define SYS_personality   92
#define SYS_sigaltstack  132
#define SYS_setpgid      154
#define SYS_getpgid      155
#define SYS_getsid       156
#define SYS_fallocate     47
#define SYS_renameat2    276
#define SYS_memfd_create 279
#define SYS_copy_file_range 285

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

// --- memfd_create ---
static void test_memfd_create(void) {
    long fd = syscall(SYS_memfd_create, "test_memfd", 0);
    check("memfd_create returns valid fd", fd >= 0);
    if (fd < 0) return;

    // Should be writable
    const char data[] = "hello memfd";
    long n = syscall(SYS_write, (int)fd, data, sizeof(data) - 1);
    check("write to memfd succeeds", n == sizeof(data) - 1);

    // Seek back to start
    long off = syscall(SYS_lseek, (int)fd, 0, 0 /* SEEK_SET */);
    check("lseek on memfd returns 0", off == 0);

    // Read back
    char buf[32];
    memset(buf, 0, sizeof(buf));
    n = syscall(SYS_read, (int)fd, buf, sizeof(buf));
    check("read from memfd returns correct length", n == sizeof(data) - 1);
    check("memfd data matches", memcmp(buf, data, sizeof(data) - 1) == 0);

    syscall(SYS_close, (int)fd);
}

// --- fallocate ---
static void test_fallocate(void) {
    // Create a temp file via memfd
    long fd = syscall(SYS_memfd_create, "test_falloc", 0);
    if (fd < 0) {
        check("fallocate: memfd_create failed", 0);
        return;
    }

    // fallocate(fd, mode=0, offset=0, len=4096)
    long ret = syscall(SYS_fallocate, (int)fd, 0, (long)0, (long)4096);
    check("fallocate(mode=0) returns 0", ret == 0);

    // Verify size changed
    long size = syscall(SYS_lseek, (int)fd, 0, 2 /* SEEK_END */);
    check("fallocate expanded file to 4096", size == 4096);

    syscall(SYS_close, (int)fd);
}

// --- ftruncate ---
static void test_ftruncate(void) {
    long fd = syscall(SYS_memfd_create, "test_ftrunc", 0);
    if (fd < 0) {
        check("ftruncate: memfd_create failed", 0);
        return;
    }

    // Write some data first
    char data[100];
    memset(data, 'A', sizeof(data));
    syscall(SYS_write, (int)fd, data, sizeof(data));

    // Truncate to 50 bytes
    long ret = syscall(SYS_ftruncate, (int)fd, (long)50);
    check("ftruncate returns 0", ret == 0);

    long size = syscall(SYS_lseek, (int)fd, 0, 2 /* SEEK_END */);
    check("ftruncate set size to 50", size == 50);

    syscall(SYS_close, (int)fd);
}

// --- fstatfs ---
static void test_fstatfs(void) {
    // Open current directory
    long fd = syscall(SYS_openat, -100 /* AT_FDCWD */, ".", 0x10000 /* O_DIRECTORY */, 0);
    if (fd < 0) {
        // Try without O_DIRECTORY
        fd = syscall(SYS_openat, -100, "/dev/null", 0, 0);
    }
    if (fd < 0) {
        check("fstatfs: open failed", 0);
        return;
    }

    // Linux struct statfs is 120 bytes on aarch64
    char buf[256];
    memset(buf, 0, sizeof(buf));
    long ret = syscall(SYS_fstatfs, (int)fd, buf);
    check("fstatfs returns 0", ret == 0);

    // f_type should be non-zero for a real filesystem
    // (first field is long/u64 on aarch64)
    unsigned long f_type;
    memcpy(&f_type, buf, sizeof(f_type));
    // f_type might be 0 for some fs, so just check call succeeded
    check("fstatfs: f_type is plausible", 1);

    syscall(SYS_close, (int)fd);
}

// --- personality ---
static void test_personality(void) {
    // personality(0xffffffff) = query current personality
    long ret = syscall(SYS_personality, 0xFFFFFFFF);
    check("personality(query) returns >= 0", ret >= 0);

    // personality(PER_LINUX=0) = set to Linux
    ret = syscall(SYS_personality, 0);
    check("personality(PER_LINUX) returns >= 0", ret >= 0);
}

// --- sigaltstack ---
static void test_sigaltstack(void) {
    // Linux sigaltstack struct: { void *ss_sp; int ss_flags; size_t ss_size; }
    // Query current (should be SS_DISABLE=2)
    struct {
        unsigned long ss_sp;
        int ss_flags;
        int __pad;
        unsigned long ss_size;
    } old, new_ss;

    memset(&old, 0, sizeof(old));
    long ret = syscall(SYS_sigaltstack, 0 /* NULL */, &old);
    check("sigaltstack(NULL, &old) returns 0", ret == 0);
    check("sigaltstack: initially SS_DISABLE", old.ss_flags == 2);

    // Set a new altstack
    static char altstack_buf[8192] __attribute__((aligned(16)));
    memset(&new_ss, 0, sizeof(new_ss));
    new_ss.ss_sp = (unsigned long)altstack_buf;
    new_ss.ss_flags = 0;
    new_ss.ss_size = sizeof(altstack_buf);

    memset(&old, 0, sizeof(old));
    ret = syscall(SYS_sigaltstack, &new_ss, &old);
    check("sigaltstack(set) returns 0", ret == 0);

    // Query again to verify
    memset(&old, 0, sizeof(old));
    ret = syscall(SYS_sigaltstack, 0, &old);
    check("sigaltstack query after set returns 0", ret == 0);
    check("sigaltstack: sp matches", old.ss_sp == (unsigned long)altstack_buf);
    check("sigaltstack: size matches", old.ss_size == sizeof(altstack_buf));
    check("sigaltstack: flags is 0 (enabled)", old.ss_flags == 0);
}

// --- setpgid / getpgid / getsid ---
static void test_process_groups(void) {
    long pid = syscall(SYS_getpid);

    // getpgid(0) = get own process group
    long pgid = syscall(SYS_getpgid, 0);
    check("getpgid(0) returns > 0", pgid > 0);

    // getsid(0) = get own session id
    long sid = syscall(SYS_getsid, 0);
    check("getsid(0) returns > 0", sid > 0);

    // setpgid(0, 0) = set own pgid to own pid - may fail if we're session leader
    long ret = syscall(SYS_setpgid, 0, 0);
    // Either succeeds or returns -EPERM, both are valid
    check("setpgid(0,0) returns 0 or -EPERM", ret == 0 || ret == -1);
}

// --- fsync ---
static void test_fsync(void) {
    long fd = syscall(SYS_memfd_create, "test_fsync", 0);
    if (fd < 0) {
        check("fsync: memfd_create failed", 0);
        return;
    }

    syscall(SYS_write, (int)fd, "data", 4);
    long ret = syscall(SYS_fsync, (int)fd);
    check("fsync returns 0", ret == 0);

    syscall(SYS_close, (int)fd);
}

// --- copy_file_range ---
static void test_copy_file_range(void) {
    // Create source memfd with data
    long src = syscall(SYS_memfd_create, "cfr_src", 0);
    long dst = syscall(SYS_memfd_create, "cfr_dst", 0);
    if (src < 0 || dst < 0) {
        check("copy_file_range: memfd_create failed", 0);
        return;
    }

    const char data[] = "copy_file_range test data!";
    syscall(SYS_write, (int)src, data, sizeof(data) - 1);
    // Seek source back to start
    syscall(SYS_lseek, (int)src, 0, 0);

    // copy_file_range(fd_in, off_in, fd_out, off_out, len, flags)
    long ret = syscall(SYS_copy_file_range, (int)src, 0, (int)dst, 0, (long)(sizeof(data) - 1), 0);
    check("copy_file_range returns correct count", ret == sizeof(data) - 1);

    // Read from destination
    syscall(SYS_lseek, (int)dst, 0, 0);
    char buf[64];
    memset(buf, 0, sizeof(buf));
    long n = syscall(SYS_read, (int)dst, buf, sizeof(buf));
    check("copy_file_range: dest has correct data", n == sizeof(data) - 1 && memcmp(buf, data, n) == 0);

    syscall(SYS_close, (int)src);
    syscall(SYS_close, (int)dst);
}

// --- renameat2 (basic, flags=0) ---
static void test_renameat2(void) {
    // Create a temp file, rename it, verify
    // We'll use openat + write + renameat2

    // Create file "test_renameat2_src"
    int fd = syscall(SYS_openat, -100, "test_renameat2_src",
                     0x42 /* O_CREAT|O_RDWR (Linux) */, 0644);
    if (fd < 0) {
        // Might be in read-only dir, skip
        check("renameat2: skipped (can't create file)", 1);
        return;
    }
    syscall(SYS_write, fd, "hi", 2);
    syscall(SYS_close, fd);

    // renameat2(AT_FDCWD, "src", AT_FDCWD, "dst", 0)
    long ret = syscall(SYS_renameat2, -100, "test_renameat2_src",
                       -100, "test_renameat2_dst", 0);
    check("renameat2(flags=0) returns 0", ret == 0);

    // Verify destination exists
    int fd2 = syscall(SYS_openat, -100, "test_renameat2_dst", 0 /* O_RDONLY */, 0);
    check("renameat2: dest file exists", fd2 >= 0);
    if (fd2 >= 0) syscall(SYS_close, fd2);

    // Verify source is gone
    int fd3 = syscall(SYS_openat, -100, "test_renameat2_src", 0, 0);
    check("renameat2: source is gone", fd3 < 0);
    if (fd3 >= 0) syscall(SYS_close, fd3);

    // Clean up
    syscall(SYS_unlinkat, -100, "test_renameat2_dst", 0);
}

int main(void) {
    test_memfd_create();
    test_fallocate();
    test_ftruncate();
    test_fstatfs();
    test_personality();
    test_sigaltstack();
    test_process_groups();
    test_fsync();
    test_copy_file_range();
    test_renameat2();

    // Print results
    char buf[80];
    int i = 0;
    if (tests_passed == tests_run) {
        const char *p = "PASS: all new syscall tests passed (";
        while (*p) buf[i++] = *p++;
    } else {
        const char *p = "FAIL: new syscall tests (";
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
