// Test: signal safety under concurrent rt_sigaction + rapid signal delivery
// Verifies that installing/reading signal handlers while signals fire rapidly
// does not deadlock. Uses kill(getpid(), SIGUSR1) for signal delivery alongside
// rt_sigaction calls. If there were a mutex deadlock, this would hang.
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>

// aarch64 Linux syscall numbers
#define __NR_rt_sigaction  134
#define __NR_kill          129
#define __NR_getpid        172

// Linux signal numbers
#define LINUX_SIGUSR1      10
#define LINUX_SIGUSR2      12

static volatile int usr1_count = 0;
static volatile int usr2_count = 0;

static void usr1_handler(int sig) {
    (void)sig;
    usr1_count++;
}

static void usr2_handler(int sig) {
    (void)sig;
    usr2_count++;
}

// Linux struct sigaction layout (aarch64):
struct linux_sigaction {
    unsigned long sa_handler;
    unsigned long sa_flags;
    unsigned long sa_restorer;
    unsigned long sa_mask;
};

int main(void) {
    long pid = syscall(__NR_getpid);

    // Install SIGUSR1 handler
    struct linux_sigaction sa1, old;
    memset(&sa1, 0, sizeof(sa1));
    sa1.sa_handler = (unsigned long)usr1_handler;

    long ret = syscall(__NR_rt_sigaction, LINUX_SIGUSR1, &sa1, 0, 8);
    if (ret != 0) {
        const char msg[] = "FAIL: rt_sigaction for SIGUSR1 failed\n";
        write(1, msg, sizeof(msg) - 1);
        return 1;
    }

    // Install SIGUSR2 handler
    struct linux_sigaction sa2;
    memset(&sa2, 0, sizeof(sa2));
    sa2.sa_handler = (unsigned long)usr2_handler;
    ret = syscall(__NR_rt_sigaction, LINUX_SIGUSR2, &sa2, 0, 8);
    if (ret != 0) {
        const char msg[] = "FAIL: rt_sigaction for SIGUSR2 failed\n";
        write(1, msg, sizeof(msg) - 1);
        return 1;
    }

    // Stress test: interleave rt_sigaction reads/writes with kill() signals.
    // With a mutex-based sigaction table, this would deadlock when a signal
    // arrives while the mutex is held by do_rt_sigaction.
    int iterations = 5000;
    struct linux_sigaction check;

    for (int i = 0; i < iterations; i++) {
        // Send SIGUSR1 to self
        syscall(__NR_kill, (int)pid, LINUX_SIGUSR1);

        // Immediately read/write sigaction (exercises concurrent access)
        syscall(__NR_rt_sigaction, LINUX_SIGUSR1, &sa1, &check, 8);

        // Send SIGUSR2 to self
        syscall(__NR_kill, (int)pid, LINUX_SIGUSR2);

        // Read back SIGUSR2 handler
        memset(&check, 0, sizeof(check));
        syscall(__NR_rt_sigaction, LINUX_SIGUSR2, 0, &check, 8);

        // Verify the handler address wasn't corrupted
        if (check.sa_handler != (unsigned long)usr2_handler) {
            const char msg[] = "FAIL: handler address corrupted during concurrent access\n";
            write(1, msg, sizeof(msg) - 1);
            return 1;
        }
    }

    // Verify we got signals
    if (usr1_count == 0 || usr2_count == 0) {
        const char msg[] = "FAIL: signals not received\n";
        write(1, msg, sizeof(msg) - 1);
        return 1;
    }

    // Build output message
    char buf[128];
    int pos = 0;
    const char *p = "PASS: signal safety (";
    while (*p) buf[pos++] = *p++;

    // Print usr1_count
    int v = usr1_count;
    char digits[10];
    int d = 0;
    if (v == 0) digits[d++] = '0';
    while (v > 0) { digits[d++] = '0' + (v % 10); v /= 10; }
    while (d > 0) buf[pos++] = digits[--d];

    p = " USR1, ";
    while (*p) buf[pos++] = *p++;

    v = usr2_count;
    d = 0;
    if (v == 0) digits[d++] = '0';
    while (v > 0) { digits[d++] = '0' + (v % 10); v /= 10; }
    while (d > 0) buf[pos++] = digits[--d];

    p = " USR2, ";
    while (*p) buf[pos++] = *p++;

    v = iterations;
    d = 0;
    while (v > 0) { digits[d++] = '0' + (v % 10); v /= 10; }
    while (d > 0) buf[pos++] = digits[--d];

    p = " sigaction calls, no deadlock)\n";
    while (*p) buf[pos++] = *p++;

    write(1, buf, pos);
    return 0;
}
