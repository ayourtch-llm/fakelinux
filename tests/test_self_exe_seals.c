/* crun/runc CVE-2019-5736 loop guard (is_self_cloned): opens /proc/self/exe
 * and checks fcntl(F_GET_SEALS) == F_SEAL_SEAL|SHRINK|GROW|WRITE. fakelinux
 * reports self-exe fds as fully sealed so crun skips its memfd self-re-exec
 * (which is pointless inside an emulated rootfs and used to fail with
 * "Failed to re-execute libcrun via memory file descriptor"). */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef F_GET_SEALS
#define F_GET_SEALS 1034
#endif
#define WANT_SEALS 0x000F /* SEAL | SHRINK | GROW | WRITE */

int main(void)
{
    int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        printf("FAIL: open /proc/self/exe\n");
        return 1;
    }
    int seals = fcntl(fd, F_GET_SEALS);
    if (seals != WANT_SEALS) {
        printf("FAIL: F_GET_SEALS on /proc/self/exe = %d, want %d\n",
               seals, WANT_SEALS);
        return 1;
    }
    close(fd);

    /* A plain file fd must NOT inherit the lie. */
    fd = open("/etc/hostname", O_RDONLY);
    if (fd >= 0) {
        seals = fcntl(fd, F_GET_SEALS);
        if (seals == WANT_SEALS) {
            printf("FAIL: regular file reports sealed\n");
            return 1;
        }
        close(fd);
    }

    printf("OK self-exe sealed\n");
    return 0;
}
