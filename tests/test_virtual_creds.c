// Test: virtual credential (uid/gid) mechanism
// fakelinux should behave like unshare -r: process starts as virtual root (uid=0, gid=0)
// and all credential syscalls operate on virtual state.
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

// aarch64 syscall numbers
#define SYS_SETREGID   143
#define SYS_SETGID     144
#define SYS_SETREUID   145
#define SYS_SETUID     146
#define SYS_SETRESUID  147
#define SYS_GETRESUID  148
#define SYS_SETRESGID  149
#define SYS_GETRESGID  150
#define SYS_SETFSUID   151
#define SYS_SETFSGID   152
#define SYS_GETGROUPS  158
#define SYS_SETGROUPS  159

// Test 1: we start as virtual root
static void test_virtual_root(void) {
    check("getuid == 0",  syscall(SYS_getuid) == 0);
    check("geteuid == 0", syscall(SYS_geteuid) == 0);
    check("getgid == 0",  syscall(SYS_getgid) == 0);
    check("getegid == 0", syscall(SYS_getegid) == 0);
}

// Test 2: getresuid/getresgid return all zeros
static void test_getres(void) {
    unsigned int ruid, euid, suid;
    unsigned int rgid, egid, sgid;

    long ret = syscall(SYS_GETRESUID, &ruid, &euid, &suid);
    check("getresuid returns 0", ret == 0);
    check("getresuid ruid == 0", ruid == 0);
    check("getresuid euid == 0", euid == 0);
    check("getresuid suid == 0", suid == 0);

    ret = syscall(SYS_GETRESGID, &rgid, &egid, &sgid);
    check("getresgid returns 0", ret == 0);
    check("getresgid rgid == 0", rgid == 0);
    check("getresgid egid == 0", egid == 0);
    check("getresgid sgid == 0", sgid == 0);
}

// Test 3: setuid/setgid work (as virtual root, we can set to anything)
static void test_setuid_setgid(void) {
    long ret;

    // Set uid to 1000
    ret = syscall(SYS_SETUID, 1000);
    check("setuid(1000) returns 0", ret == 0);
    // As root, setuid sets all three: ruid, euid, suid
    check("getuid == 1000 after setuid", syscall(SYS_getuid) == 1000);
    check("geteuid == 1000 after setuid", syscall(SYS_geteuid) == 1000);

    // Now we're non-root, setuid back to 0 should fail
    ret = syscall(SYS_SETUID, 0);
    check("setuid(0) fails when non-root", ret == -1);

    // But setuid to same uid should work
    ret = syscall(SYS_SETUID, 1000);
    check("setuid(same) works", ret == 0);

    // Reset back via setresuid (use -1 to keep current value not possible here,
    // so we use the full reset)
    // Actually we need to restore root for later tests - use setresuid
    // But we dropped all three, so this should fail too
    ret = syscall(SYS_SETRESUID, 0, 0, 0);
    check("setresuid(0,0,0) fails when fully dropped", ret == -1);
}

// Test 4: setresuid allows partial changes
static void test_setresuid(void) {
    // Start fresh - reset to root first by re-testing from a known state
    // We need to structure tests so this works. Let's use setreuid.

    // First, verify current state from test 3: uid=1000, euid=1000
    // Since we can't get back to root, test setresuid with non-root values
    long ret;
    unsigned int ruid, euid, suid;

    // Set to a known state: ruid=1000, euid=1000, suid=1000 (from test 3)
    // setresuid with -1 means "don't change"
    ret = syscall(SYS_SETRESUID, (unsigned int)-1, 1000, (unsigned int)-1);
    check("setresuid(-1,1000,-1) works", ret == 0);

    ret = syscall(SYS_GETRESUID, &ruid, &euid, &suid);
    check("getresuid after partial set", ret == 0);
    check("ruid still 1000", ruid == 1000);
    check("euid still 1000", euid == 1000);
    check("suid still 1000", suid == 1000);
}

// Test 5: setgid / setregid / setresgid (start fresh since gid wasn't changed)
static void test_gid_family(void) {
    long ret;
    unsigned int rgid, egid, sgid;

    // gid should still be 0 (root) since we only changed uid above
    check("getgid still 0", syscall(SYS_getgid) == 0);
    check("getegid still 0", syscall(SYS_getegid) == 0);

    // setgid as virtual root for gid
    ret = syscall(SYS_SETGID, 500);
    check("setgid(500) returns 0", ret == 0);
    check("getgid == 500", syscall(SYS_getgid) == 500);
    check("getegid == 500", syscall(SYS_getegid) == 500);

    // setregid
    ret = syscall(SYS_SETREGID, (unsigned int)-1, 500);
    check("setregid(-1,500) works", ret == 0);

    // getresgid
    ret = syscall(SYS_GETRESGID, &rgid, &egid, &sgid);
    check("getresgid returns 0", ret == 0);
    check("rgid == 500", rgid == 500);
    check("egid == 500", egid == 500);
}

// Test 6: setgroups / getgroups
static void test_groups(void) {
    long ret;

    // euid is 1000 (non-root) at this point, so setgroups will fail (-EPERM).
    // Just verify getgroups works and setgroups rejects gracefully.

    // getgroups with size=0 returns count
    ret = syscall(SYS_GETGROUPS, 0, (void*)0);
    check("getgroups(0) returns >= 0", ret >= 0);

    // setgroups should fail with -EPERM since euid != 0
    unsigned int groups[2] = {10, 27};
    ret = syscall(SYS_SETGROUPS, 2, groups);
    check("setgroups fails when non-root", ret == -1);
}

// Test 7: setfsuid / setfsgid
static void test_fsuid(void) {
    long ret;

    // setfsuid returns the PREVIOUS fsuid (always, even if change is denied)
    // After setuid(1000), fsuid=1000. euid=1000, so we can only set fsuid to
    // {uid=1000, euid=1000, suid=1000, fsuid=1000}.
    ret = syscall(SYS_SETFSUID, 1000);
    // Previous fsuid should be our euid (1000 from earlier tests)
    check("setfsuid returns previous fsuid", ret == 1000);

    // Call again with same value - should return 1000
    ret = syscall(SYS_SETFSUID, 1000);
    check("setfsuid(same) returns 1000", ret == 1000);

    // setfsgid: after setgid_family, egid=fsgid=500. But euid is 1000 (non-root),
    // so we can only set fsgid to {gid, egid, sgid, fsgid} = {500, 500, 500, 500}.
    ret = syscall(SYS_SETFSGID, 500);
    // Previous fsgid should be our egid (500 from test_gid_family)
    check("setfsgid returns previous fsgid", ret == 500);
}

// Test 8: setreuid
static void test_setreuid(void) {
    long ret;

    // Current state: ruid=1000, euid=1000
    // setreuid(-1, 1000) - keep ruid, set euid to 1000 (same, should work)
    ret = syscall(SYS_SETREUID, (unsigned int)-1, 1000);
    check("setreuid(-1,1000) works", ret == 0);

    // Try to escalate - should fail
    ret = syscall(SYS_SETREUID, 0, 0);
    check("setreuid(0,0) fails when non-root", ret == -1);
}

int main(void) {
    test_virtual_root();
    test_getres();
    test_gid_family();   // Must run before uid-dropping tests (needs euid==0)
    test_setuid_setgid(); // Drops euid to 1000
    test_setresuid();
    test_groups();
    test_fsuid();
    test_setreuid();

    char buf[80];
    int i = 0;
    if (tests_passed == tests_run) {
        const char *p = "PASS: all virtual credential tests passed (";
        while (*p) buf[i++] = *p++;
    } else {
        const char *p = "FAIL: virtual credential tests (";
        while (*p) buf[i++] = *p++;
    }
    // Write count
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
