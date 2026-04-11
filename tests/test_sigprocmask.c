// Test: block SIGUSR1, send to self (should be pending), unblock, verify handler ran.
#include <signal.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>

static volatile int handler_ran = 0;

static void sigusr1_handler(int sig) {
    (void)sig;
    handler_ran = 1;
}

int main(void) {
    struct sigaction sa;
    sa.sa_handler = sigusr1_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, (void*)0);

    // Block SIGUSR1
    sigset_t set, oldset;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, &oldset);

    // Send SIGUSR1 to self -- should be pending, not delivered yet
    kill(getpid(), SIGUSR1);

    if (handler_ran) {
        const char msg[] = "FAIL: handler ran while SIGUSR1 was blocked\n";
        write(1, msg, sizeof(msg) - 1);
        return 1;
    }

    // Unblock SIGUSR1 -- pending signal should now be delivered
    sigprocmask(SIG_UNBLOCK, &set, (void*)0);

    if (handler_ran) {
        const char msg[] = "PASS: SIGUSR1 delivered after unblock\n";
        write(1, msg, sizeof(msg) - 1);
        return 0;
    } else {
        const char msg[] = "FAIL: SIGUSR1 not delivered after unblock\n";
        write(1, msg, sizeof(msg) - 1);
        return 1;
    }
}
