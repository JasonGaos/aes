#ifndef AES_H
#define AES_H

#include <stddef.h>
#include <stdint.h>

#define AES_BLOCK_SIZE 16u
#define AES_KEY_SIZE 16u
#define AES_IV_SIZE 16u

#ifdef __cplusplus
extern "C" {
#endif

/*
 * AES-128 in CTR mode.
 * `key` must point to 16 bytes.
 * `iv` must point to a 16-byte initial counter block.
 * The counter is incremented as a big-endian 128-bit integer.
 */
void aes_encrypt_msg(const uint8_t *key,
                     const uint8_t *iv,
                     const uint8_t *plaintext,
                     uint8_t *ciphertext,
                     const size_t msg_len);

void aes_decrypt_msg(const uint8_t *key,
                     const uint8_t *iv,
                     const uint8_t *ciphertext,
                     uint8_t *plaintext,
                     const size_t msg_len);

#ifdef __cplusplus
}
#endif

#endif
