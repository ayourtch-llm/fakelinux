// Test: send SIGUSR1 to self 3 times, verify counter == 3 (proves sigreturn works).
#include <signal.h>
#include <unistd.h>
#include <sys/syscall.h>

static volatile int counter = 0;

static void sigusr1_handler(int sig) {
    (void)sig;
    counter++;
}

int main(void) {
    struct sigaction sa;
    sa.sa_handler = sigusr1_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, (void*)0);

    // Send SIGUSR1 to self 3 times
    kill(getpid(), SIGUSR1);
    kill(getpid(), SIGUSR1);
    kill(getpid(), SIGUSR1);

    if (counter == 3) {
        const char msg[] = "PASS: signal handler ran 3 times\n";
        write(1, msg, sizeof(msg) - 1);
        return 0;
    } else {
        // Print failure with counter value
        char buf[64];
        const char prefix[] = "FAIL: counter=";
        int i = 0;
        for (int j = 0; prefix[j]; j++) buf[i++] = prefix[j];
        buf[i++] = '0' + (counter % 10);
        buf[i++] = ' ';
        buf[i++] = '(';
        buf[i++] = 'e';
        buf[i++] = 'x';
        buf[i++] = 'p';
        buf[i++] = 'e';
        buf[i++] = 'c';
        buf[i++] = 't';
        buf[i++] = 'e';
        buf[i++] = 'd';
        buf[i++] = ' ';
        buf[i++] = '3';
        buf[i++] = ')';
        buf[i++] = '\n';
        write(1, buf, i);
        return 1;
    }
}
