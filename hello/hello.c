/* Trivial hello-world used to smoke-test the fakelinux ELF loader and syscall
 * emulation across libc/link-mode variants (static, PIE, dynamic; glibc/musl).
 * Build with ./hello/build.sh. */
#include <stdio.h>

int main(void) {
    printf("Hello from a fakelinux test binary\n");
    return 0;
}
