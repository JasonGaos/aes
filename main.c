#include "aes.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define BENCHMARK_MSG_LEN (64u * 1024u)
#define BENCHMARK_MIN_SECONDS 0.20

static volatile uint8_t benchmark_sink = 0u;

static void print_hex(const uint8_t *buffer, size_t length) {
    size_t i;
    for (i = 0; i < length; ++i) {
        printf("%02x", buffer[i]);
    }
    putchar('\n');
}

static int expect_bytes(const char *label,
                        const uint8_t *actual,
                        const uint8_t *expected,
                        size_t length) {
    if (memcmp(actual, expected, length) == 0) {
        printf("[PASS] %s\n", label);
        return 1;
    }

    printf("[FAIL] %s\n", label);
    printf("  expected: ");
    print_hex(expected, length);
    printf("  actual:   ");
    print_hex(actual, length);
    return 0;
}

static double now_seconds(void) {
    struct timespec ts;
    (void)timespec_get(&ts, TIME_UTC);
    return (double)ts.tv_sec + ((double)ts.tv_nsec / 1000000000.0);
}

static double benchmark_encrypt_gbps(const uint8_t *key,
                                     const uint8_t *iv,
                                     const uint8_t *plaintext,
                                     uint8_t *ciphertext,
                                     size_t msg_len) {
    size_t iterations = 1u;
    double elapsed = 0.0;

    do {
        size_t i;
        const double start = now_seconds();

        for (i = 0u; i < iterations; ++i) {
            aes_encrypt_msg(key, iv, plaintext, ciphertext, msg_len);
            benchmark_sink ^= ciphertext[i % msg_len];
        }

        elapsed = now_seconds() - start;

        if (elapsed < BENCHMARK_MIN_SECONDS) {
            iterations *= 2u;
        }
    } while (elapsed < BENCHMARK_MIN_SECONDS && iterations <= (1u << 22));

    return ((double)msg_len * (double)iterations) / elapsed / 1000000000.0;
}

static double benchmark_decrypt_gbps(const uint8_t *key,
                                     const uint8_t *iv,
                                     const uint8_t *ciphertext,
                                     uint8_t *plaintext,
                                     size_t msg_len) {
    size_t iterations = 1u;
    double elapsed = 0.0;

    do {
        size_t i;
        const double start = now_seconds();

        for (i = 0u; i < iterations; ++i) {
            aes_decrypt_msg(key, iv, ciphertext, plaintext, msg_len);
            benchmark_sink ^= plaintext[i % msg_len];
        }

        elapsed = now_seconds() - start;

        if (elapsed < BENCHMARK_MIN_SECONDS) {
            iterations *= 2u;
        }
    } while (elapsed < BENCHMARK_MIN_SECONDS && iterations <= (1u << 22));

    return ((double)msg_len * (double)iterations) / elapsed / 1000000000.0;
}

static int run_throughput_benchmark(void) {
    const uint8_t key[AES_KEY_SIZE] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81
    };
    const uint8_t iv[AES_IV_SIZE] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
    };
    uint8_t *plaintext = (uint8_t *)malloc(BENCHMARK_MSG_LEN);
    uint8_t *ciphertext = (uint8_t *)malloc(BENCHMARK_MSG_LEN);
    uint8_t *recovered = (uint8_t *)malloc(BENCHMARK_MSG_LEN);
    size_t i;
    double encrypt_gbps;
    double decrypt_gbps;

    if (plaintext == NULL || ciphertext == NULL || recovered == NULL) {
        printf("[FAIL] Throughput benchmark allocation\n");
        free(plaintext);
        free(ciphertext);
        free(recovered);
        return 0;
    }

    for (i = 0u; i < BENCHMARK_MSG_LEN; ++i) {
        plaintext[i] = (uint8_t)(i & 0xffu);
    }

    aes_encrypt_msg(key, iv, plaintext, ciphertext, BENCHMARK_MSG_LEN);

    encrypt_gbps = benchmark_encrypt_gbps(key, iv, plaintext, ciphertext, BENCHMARK_MSG_LEN);
    decrypt_gbps = benchmark_decrypt_gbps(key, iv, ciphertext, recovered, BENCHMARK_MSG_LEN);

    printf("Encrypt throughput (64 KB): %.3f GB/s\n", encrypt_gbps);
    printf("Decrypt throughput (64 KB): %.3f GB/s\n", decrypt_gbps);

    free(plaintext);
    free(ciphertext);
    free(recovered);
    return 1;
}

int main(void) {
    int ok = 1;

    const uint8_t nist_key[AES_KEY_SIZE] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    const uint8_t nist_iv[AES_IV_SIZE] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
    };

    const uint8_t nist_plaintext[64] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    };

    const uint8_t nist_ciphertext[64] = {
        0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
        0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
        0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff,
        0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
        0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e,
        0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
        0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1,
        0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee
    };

    uint8_t encrypted[sizeof(nist_plaintext)];
    uint8_t decrypted[sizeof(nist_plaintext)];

    aes_encrypt_msg(nist_key, nist_iv, nist_plaintext, encrypted, sizeof(nist_plaintext));
    ok &= expect_bytes("NIST AES-128-CTR encrypt", encrypted, nist_ciphertext, sizeof(encrypted));

    aes_decrypt_msg(nist_key, nist_iv, nist_ciphertext, decrypted, sizeof(nist_ciphertext));
    ok &= expect_bytes("NIST AES-128-CTR decrypt", decrypted, nist_plaintext, sizeof(decrypted));

    {
        const uint8_t key[AES_KEY_SIZE] = {
            0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
        };
        const uint8_t iv[AES_IV_SIZE] = {
            0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef,
            0xca, 0xfe, 0xba, 0xbe, 0x12, 0x34, 0x56, 0x78
        };
        const uint8_t message[] = "CTR mode handles partial blocks correctly.";
        uint8_t ciphertext[sizeof(message) - 1u];
        uint8_t plaintext[sizeof(message) - 1u];
        const size_t message_len = sizeof(message) - 1u;

        aes_encrypt_msg(key, iv, message, ciphertext, message_len);
        aes_decrypt_msg(key, iv, ciphertext, plaintext, message_len);
        ok &= expect_bytes("Partial-block round trip", plaintext, message, message_len);
    }

    if (!ok) {
        return 1;
    }

    printf("All AES-CTR tests passed.\n");
    ok &= run_throughput_benchmark();
    if (!ok) {
        return 1;
    }

    return 0;
}
