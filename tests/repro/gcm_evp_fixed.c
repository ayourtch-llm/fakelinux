// Minimal C/OpenSSL AES-GCM decrypt repro matching gcm_signal_corruption.py.
//
// Build inside the guest:
//   cc -O2 -Wall -Wextra -o /tmp/gcm_evp_fixed /tmp/gcm_evp_fixed.c -lcrypto
// Run:
//   /tmp/gcm_evp_fixed [iterations] [payload_size] [sigalrm_interval_usec]
//
// interval=0 disables SIGALRM. The ciphertext/tag are computed once; each
// iteration allocates a fresh EVP decrypt context and decrypts the same
// ciphertext into a fixed reused output buffer.
#include <openssl/evp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

static volatile unsigned long ticks = 0;

static void on_alarm(int signo) {
    (void)signo;
    ticks++;
}

static int encrypt_once(const unsigned char *key, const unsigned char *nonce,
                        const unsigned char *pt, int psize,
                        unsigned char *ct, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, outl = 0;
    if (ctx == NULL) return 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) return 0;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) return 0;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) return 0;
    if (EVP_EncryptUpdate(ctx, ct, &len, pt, psize) != 1) return 0;
    outl = len;
    if (EVP_EncryptFinal_ex(ctx, ct + outl, &len) != 1) return 0;
    outl += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) return 0;
    EVP_CIPHER_CTX_free(ctx);
    return outl;
}

static int decrypt_once(const unsigned char *key, const unsigned char *nonce,
                        const unsigned char *ct, int clen,
                        const unsigned char *tag, unsigned char *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, outl = 0, ok = 0;
    if (ctx == NULL) return 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;
    if (EVP_DecryptUpdate(ctx, out, &len, ct, clen) != 1) goto done;
    outl = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1) goto done;
    ok = EVP_DecryptFinal_ex(ctx, out + outl, &len) == 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int main(int argc, char **argv) {
    int iters = argc > 1 ? atoi(argv[1]) : 8000;
    int psize = argc > 2 ? atoi(argv[2]) : 1970;
    int interval_us = argc > 3 ? atoi(argv[3]) : 200;

    unsigned char key[32], nonce[12], tag[16];
    for (int i = 0; i < 32; i++) key[i] = (unsigned char)i;
    for (int i = 0; i < 12; i++) nonce[i] = (unsigned char)i;

    unsigned char *pt = malloc((size_t)psize);
    unsigned char *ct = malloc((size_t)psize + 32);
    unsigned char *out = malloc((size_t)psize + 16);
    if (pt == NULL || ct == NULL || out == NULL) {
        fprintf(stderr, "malloc failed\n");
        return 2;
    }
    memset(pt, 0x58, (size_t)psize);
    memset(out, 0, (size_t)psize + 16);

    int clen = encrypt_once(key, nonce, pt, psize, ct, tag);
    if (clen != psize) {
        fprintf(stderr, "encrypt failed clen=%d\n", clen);
        return 2;
    }

    printf("gcm_evp_fixed: out_buf=%p len=%d psize=%d iters=%d interval_us=%d\n",
           (void *)out, psize + 16, psize, iters, interval_us);
    fflush(stdout);

    if (interval_us > 0) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = on_alarm;
        sigemptyset(&sa.sa_mask);
        if (sigaction(SIGALRM, &sa, NULL) != 0) {
            perror("sigaction");
            return 2;
        }
        struct itimerval it;
        memset(&it, 0, sizeof(it));
        it.it_value.tv_usec = interval_us;
        it.it_interval.tv_usec = interval_us;
        if (setitimer(ITIMER_REAL, &it, NULL) != 0) {
            perror("setitimer");
            return 2;
        }
    }

    int bad = 0, tagfail = 0;
    for (int i = 0; i < iters; i++) {
        int tag_ok = decrypt_once(key, nonce, ct, clen, tag, out);
        if (!tag_ok) tagfail++;
        if (memcmp(out, pt, (size_t)psize) != 0) {
            int off = -1;
            bad++;
            for (int j = 0; j < psize; j++) {
                if (out[j] != 0x58) {
                    off = j;
                    break;
                }
            }
            if (bad <= 12) {
                int blk = off >= 0 ? (off / 16) * 16 : 0;
                printf("  iter=%d firstdiff=%d block=%d tag_ok=%d bytes=",
                       i, off, blk, tag_ok);
                for (int k = 0; k < 16 && blk + k < psize; k++) {
                    printf("%02x", out[blk + k]);
                }
                printf("\n");
            }
        }
        if (i % 500 == 0) {
            printf("iter %d bad %d tagfail %d ticks %lu\n", i, bad, tagfail, ticks);
            fflush(stdout);
        }
    }

    if (interval_us > 0) {
        struct itimerval it;
        memset(&it, 0, sizeof(it));
        setitimer(ITIMER_REAL, &it, NULL);
    }

    printf("TOTAL bad=%d tagfail=%d / %d (psize=%d, interval_us=%d, ticks=%lu)\n",
           bad, tagfail, iters, psize, interval_us, ticks);
    return bad ? 1 : 0;
}
