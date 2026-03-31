#include "aes.h"

#include <string.h>

/*
 * AES-128 block core adapted from the portable single-block AES design in
 * https://github.com/mrdcvlsc/AES and wrapped here in a plain C CTR API.
 */

#define AES128_ROUNDS 10u
#define AES128_ROUND_KEY_SIZE 176u

static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
    0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
    0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
    0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
    0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
    0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
    0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
    0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
    0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
    0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
    0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
    0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
    0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
    0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
    0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
    0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
    0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
    0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
    0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
    0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
    0x54, 0xbb, 0x16
};

static const uint8_t rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1b, 0x36
};

static void secure_zero(void *buffer, size_t length) {
    volatile uint8_t *p = (volatile uint8_t *)buffer;
    while (length-- > 0u) {
        *p++ = 0u;
    }
}

static uint8_t xtime(uint8_t value) {
    return (uint8_t)((value << 1u) ^ (((value >> 7u) & 0x01u) * 0x1bu));
}

static void sub_bytes(uint8_t state[AES_BLOCK_SIZE]) {
    size_t i;
    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        state[i] = sbox[state[i]];
    }
}

static void shift_rows(uint8_t state[AES_BLOCK_SIZE]) {
    uint8_t temp;

    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

static void mix_columns(uint8_t state[AES_BLOCK_SIZE]) {
    size_t column;
    for (column = 0; column < AES_BLOCK_SIZE; column += 4u) {
        const uint8_t s0 = state[column];
        const uint8_t s1 = state[column + 1u];
        const uint8_t s2 = state[column + 2u];
        const uint8_t s3 = state[column + 3u];
        const uint8_t sum = (uint8_t)(s0 ^ s1 ^ s2 ^ s3);
        const uint8_t first = s0;

        state[column] ^= (uint8_t)(sum ^ xtime((uint8_t)(s0 ^ s1)));
        state[column + 1u] ^= (uint8_t)(sum ^ xtime((uint8_t)(s1 ^ s2)));
        state[column + 2u] ^= (uint8_t)(sum ^ xtime((uint8_t)(s2 ^ s3)));
        state[column + 3u] ^= (uint8_t)(sum ^ xtime((uint8_t)(s3 ^ first)));
    }
}

static void add_round_key(uint8_t state[AES_BLOCK_SIZE], const uint8_t *round_key) {
    size_t i;
    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        state[i] ^= round_key[i];
    }
}

static void key_expansion(const uint8_t *key, uint8_t round_keys[AES128_ROUND_KEY_SIZE]) {
    uint8_t temp[4];
    size_t bytes_generated = AES_KEY_SIZE;
    size_t rcon_index = 0u;
    size_t i;

    memcpy(round_keys, key, AES_KEY_SIZE);

    while (bytes_generated < AES128_ROUND_KEY_SIZE) {
        for (i = 0; i < 4u; ++i) {
            temp[i] = round_keys[bytes_generated - 4u + i];
        }

        if ((bytes_generated % AES_KEY_SIZE) == 0u) {
            const uint8_t first = temp[0];
            temp[0] = sbox[temp[1]];
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[first];
            temp[0] ^= rcon[rcon_index++];
        }

        for (i = 0; i < 4u; ++i) {
            round_keys[bytes_generated] =
                (uint8_t)(round_keys[bytes_generated - AES_KEY_SIZE] ^ temp[i]);
            ++bytes_generated;
        }
    }

    secure_zero(temp, sizeof(temp));
}

static void aes_encrypt_block(const uint8_t round_keys[AES128_ROUND_KEY_SIZE],
                              const uint8_t input[AES_BLOCK_SIZE],
                              uint8_t output[AES_BLOCK_SIZE]) {
    uint8_t state[AES_BLOCK_SIZE];
    size_t round;

    memcpy(state, input, AES_BLOCK_SIZE);

    add_round_key(state, round_keys);

    for (round = 1u; round < AES128_ROUNDS; ++round) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_keys + (round * AES_BLOCK_SIZE));
    }

    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_keys + (AES128_ROUNDS * AES_BLOCK_SIZE));

    memcpy(output, state, AES_BLOCK_SIZE);
    secure_zero(state, sizeof(state));
}

static void increment_counter(uint8_t counter[AES_BLOCK_SIZE]) {
    size_t i = AES_BLOCK_SIZE;
    while (i-- > 0u) {
        counter[i] = (uint8_t)(counter[i] + 1u);
        if (counter[i] != 0u) {
            break;
        }
    }
}

static void aes_crypt_ctr(const uint8_t *key,
                          const uint8_t *iv,
                          const uint8_t *input,
                          uint8_t *output,
                          size_t msg_len) {
    uint8_t round_keys[AES128_ROUND_KEY_SIZE];
    uint8_t counter[AES_BLOCK_SIZE];
    uint8_t keystream[AES_BLOCK_SIZE];
    size_t offset = 0u;

    if (msg_len == 0u) {
        return;
    }

    if (key == NULL || iv == NULL || input == NULL || output == NULL) {
        return;
    }

    key_expansion(key, round_keys);
    memcpy(counter, iv, AES_BLOCK_SIZE);

    while (offset < msg_len) {
        size_t i;
        size_t block_len = msg_len - offset;

        if (block_len > AES_BLOCK_SIZE) {
            block_len = AES_BLOCK_SIZE;
        }

        aes_encrypt_block(round_keys, counter, keystream);

        for (i = 0u; i < block_len; ++i) {
            output[offset + i] = (uint8_t)(input[offset + i] ^ keystream[i]);
        }

        increment_counter(counter);
        offset += block_len;
    }

    secure_zero(keystream, sizeof(keystream));
    secure_zero(counter, sizeof(counter));
    secure_zero(round_keys, sizeof(round_keys));
}

void aes_encrypt_msg(const uint8_t *key,
                     const uint8_t *iv,
                     const uint8_t *plaintext,
                     uint8_t *ciphertext,
                     const size_t msg_len) {
    aes_crypt_ctr(key, iv, plaintext, ciphertext, msg_len);
}

void aes_decrypt_msg(const uint8_t *key,
                     const uint8_t *iv,
                     const uint8_t *ciphertext,
                     uint8_t *plaintext,
                     const size_t msg_len) {
    aes_crypt_ctr(key, iv, ciphertext, plaintext, msg_len);
}
