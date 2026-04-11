// Test membarrier syscall (SYS_MEMBARRIER = 283)
// MEMBARRIER_CMD_QUERY (cmd=0) should return >= 0
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>

#ifndef __NR_membarrier
#define __NR_membarrier 283
#endif

int main() {
    // MEMBARRIER_CMD_QUERY = 0, flags = 0
    long ret = syscall(__NR_membarrier, 0, 0, 0);
    if (ret < 0) {
        printf("FAIL: membarrier QUERY returned %ld\n", ret);
        return 1;
    }
    printf("OK: membarrier QUERY returned %ld\n", ret);
    return 0;
}
