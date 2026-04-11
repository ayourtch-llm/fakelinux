// Test: register SIGALRM handler, send to self via kill(), verify handler ran.
#include <signal.h>
#include <unistd.h>
#include <sys/syscall.h>

static volatile int handler_ran = 0;

static void sigalrm_handler(int sig) {
    (void)sig;
    handler_ran = 1;
}

int main(void) {
    struct sigaction sa;
    sa.sa_handler = sigalrm_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGALRM, &sa, (void*)0);

    // Send SIGALRM to self via kill syscall
    kill(getpid(), SIGALRM);

    if (handler_ran) {
        const char msg[] = "PASS: SIGALRM handler ran\n";
        write(1, msg, sizeof(msg) - 1);
        return 0;
    } else {
        const char msg[] = "FAIL: SIGALRM handler did not run\n";
        write(1, msg, sizeof(msg) - 1);
        return 1;
    }
}
