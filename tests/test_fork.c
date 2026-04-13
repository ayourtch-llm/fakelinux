/* Test that fork() returns 0 in child and child_pid in parent */
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>

int main(void) {
    pid_t pid = fork();
    if (pid < 0) {
        const char *msg = "FAIL: fork() returned -1\n";
        write(2, msg, strlen(msg));
        return 1;
    }
    if (pid == 0) {
        /* Child */
        const char *msg = "CHILD\n";
        write(1, msg, 6);
        _exit(0);
    }
    /* Parent */
    const char *msg = "PARENT\n";
    write(1, msg, 7);
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        const char *ok = "PASS: fork child/parent paths correct\n";
        write(1, ok, strlen(ok));
        return 0;
    }
    const char *fail = "FAIL: child did not exit cleanly\n";
    write(1, fail, strlen(fail));
    return 1;
}
