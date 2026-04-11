// Test: NEON/FP registers are preserved across signal delivery.
// Loads known values into NEON regs, triggers SIGALRM whose handler
// clobbers them, then verifies they are restored after sigreturn.
#include <signal.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdint.h>

static volatile int handler_ran = 0;

// Signal handler that clobbers NEON registers with known-bad values
static void sigalrm_handler(int sig) {
    (void)sig;
    handler_ran = 1;

    // Clobber caller-saved d0-d7 and callee-saved d8-d15 with 0xDEAD pattern
    double clobber = -99999.0;
    __asm__ volatile(
        "fmov d0, %x[val]\n"
        "fmov d1, %x[val]\n"
        "fmov d2, %x[val]\n"
        "fmov d3, %x[val]\n"
        "fmov d4, %x[val]\n"
        "fmov d5, %x[val]\n"
        "fmov d6, %x[val]\n"
        "fmov d7, %x[val]\n"
        "fmov d8, %x[val]\n"
        "fmov d9, %x[val]\n"
        "fmov d10, %x[val]\n"
        "fmov d11, %x[val]\n"
        "fmov d12, %x[val]\n"
        "fmov d13, %x[val]\n"
        "fmov d14, %x[val]\n"
        "fmov d15, %x[val]\n"
        "fmov d16, %x[val]\n"
        "fmov d17, %x[val]\n"
        "fmov d18, %x[val]\n"
        "fmov d19, %x[val]\n"
        "fmov d20, %x[val]\n"
        "fmov d21, %x[val]\n"
        "fmov d22, %x[val]\n"
        "fmov d23, %x[val]\n"
        "fmov d24, %x[val]\n"
        "fmov d25, %x[val]\n"
        "fmov d26, %x[val]\n"
        "fmov d27, %x[val]\n"
        "fmov d28, %x[val]\n"
        "fmov d29, %x[val]\n"
        "fmov d30, %x[val]\n"
        "fmov d31, %x[val]\n"
        :
        : [val] "r" (*(uint64_t*)&clobber)
        : "d0","d1","d2","d3","d4","d5","d6","d7",
          "d8","d9","d10","d11","d12","d13","d14","d15",
          "d16","d17","d18","d19","d20","d21","d22","d23",
          "d24","d25","d26","d27","d28","d29","d30","d31"
    );
}

// Helper: write hex u64
static void write_hex(char *buf, int *pos, uint64_t val) {
    const char hex[] = "0123456789abcdef";
    buf[(*pos)++] = '0';
    buf[(*pos)++] = 'x';
    for (int i = 60; i >= 0; i -= 4) {
        buf[(*pos)++] = hex[(val >> i) & 0xf];
    }
}

int main(void) {
    // Install SIGALRM handler
    struct sigaction sa;
    sa.sa_handler = sigalrm_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGALRM, &sa, (void*)0);

    // Load known distinct values into d0-d15 (using q regs to set full 128-bit)
    // We test a representative set: d0 (caller-saved), d8 (callee-saved),
    // plus d16-d31 range.
    // Use simple integer bit patterns cast into FP regs for easy verification.
    uint64_t val0  = 0x1000000000000000ULL;
    uint64_t val1  = 0x1100000000000001ULL;
    uint64_t val2  = 0x2200000000000002ULL;
    uint64_t val3  = 0x3300000000000003ULL;
    uint64_t val8  = 0x8800000000000008ULL;
    uint64_t val9  = 0x9900000000000009ULL;
    uint64_t val14 = 0xEE0000000000000EULL;
    uint64_t val15 = 0xFF0000000000000FULL;
    uint64_t val16 = 0x1616161616161616ULL;
    uint64_t val24 = 0x2424242424242424ULL;
    uint64_t val31 = 0x3131313131313131ULL;

    // Load values into NEON registers
    __asm__ volatile(
        "fmov d0, %x[v0]\n"
        "fmov d1, %x[v1]\n"
        "fmov d2, %x[v2]\n"
        "fmov d3, %x[v3]\n"
        "fmov d8, %x[v8]\n"
        "fmov d9, %x[v9]\n"
        "fmov d14, %x[v14]\n"
        "fmov d15, %x[v15]\n"
        "fmov d16, %x[v16]\n"
        "fmov d24, %x[v24]\n"
        "fmov d31, %x[v31]\n"
        :
        : [v0]  "r" (val0),
          [v1]  "r" (val1),
          [v2]  "r" (val2),
          [v3]  "r" (val3),
          [v8]  "r" (val8),
          [v9]  "r" (val9),
          [v14] "r" (val14),
          [v15] "r" (val15),
          [v16] "r" (val16),
          [v24] "r" (val24),
          [v31] "r" (val31)
        : "d0","d1","d2","d3","d8","d9","d14","d15","d16","d24","d31"
    );

    // Trigger SIGALRM - handler will clobber all NEON regs
    kill(getpid(), SIGALRM);

    // After handler returns (via sigreturn), read back the registers
    uint64_t got0, got1, got2, got3, got8, got9, got14, got15, got16, got24, got31;
    __asm__ volatile(
        "fmov %x[g0], d0\n"
        "fmov %x[g1], d1\n"
        "fmov %x[g2], d2\n"
        "fmov %x[g3], d3\n"
        "fmov %x[g8], d8\n"
        "fmov %x[g9], d9\n"
        "fmov %x[g14], d14\n"
        "fmov %x[g15], d15\n"
        "fmov %x[g16], d16\n"
        "fmov %x[g24], d24\n"
        "fmov %x[g31], d31\n"
        : [g0]  "=r" (got0),
          [g1]  "=r" (got1),
          [g2]  "=r" (got2),
          [g3]  "=r" (got3),
          [g8]  "=r" (got8),
          [g9]  "=r" (got9),
          [g14] "=r" (got14),
          [g15] "=r" (got15),
          [g16] "=r" (got16),
          [g24] "=r" (got24),
          [g31] "=r" (got31)
        :
        :
    );

    if (!handler_ran) {
        const char msg[] = "FAIL: signal handler did not run\n";
        write(1, msg, sizeof(msg) - 1);
        return 1;
    }

    // Check each register
    int fail = 0;
    if (got0 != val0) fail = 1;
    if (got1 != val1) fail = 1;
    if (got2 != val2) fail = 1;
    if (got3 != val3) fail = 1;
    if (got8 != val8) fail = 1;
    if (got9 != val9) fail = 1;
    if (got14 != val14) fail = 1;
    if (got15 != val15) fail = 1;
    if (got16 != val16) fail = 1;
    if (got24 != val24) fail = 1;
    if (got31 != val31) fail = 1;

    if (!fail) {
        const char msg[] = "PASS: NEON registers preserved across signal\n";
        write(1, msg, sizeof(msg) - 1);
        return 0;
    }

    // Print details on failure
    const char fmsg[] = "FAIL: NEON register mismatch after signal\n";
    write(1, fmsg, sizeof(fmsg) - 1);

    // Print which registers failed
    char buf[256];
    int pos;

    #define CHECK_REG(name, expected, actual) \
        if ((actual) != (expected)) { \
            pos = 0; \
            buf[pos++] = ' '; buf[pos++] = ' '; \
            for (const char *s = name; *s; s++) buf[pos++] = *s; \
            buf[pos++] = ':'; buf[pos++] = ' '; \
            buf[pos++] = 'e'; buf[pos++] = 'x'; buf[pos++] = 'p'; \
            buf[pos++] = '='; \
            write_hex(buf, &pos, expected); \
            buf[pos++] = ' '; \
            buf[pos++] = 'g'; buf[pos++] = 'o'; buf[pos++] = 't'; \
            buf[pos++] = '='; \
            write_hex(buf, &pos, actual); \
            buf[pos++] = '\n'; \
            write(1, buf, pos); \
        }

    CHECK_REG("d0",  val0,  got0);
    CHECK_REG("d1",  val1,  got1);
    CHECK_REG("d2",  val2,  got2);
    CHECK_REG("d3",  val3,  got3);
    CHECK_REG("d8",  val8,  got8);
    CHECK_REG("d9",  val9,  got9);
    CHECK_REG("d14", val14, got14);
    CHECK_REG("d15", val15, got15);
    CHECK_REG("d16", val16, got16);
    CHECK_REG("d24", val24, got24);
    CHECK_REG("d31", val31, got31);

    return 1;
}
