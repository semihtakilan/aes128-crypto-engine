#ifndef AES_CBC_H
#define AES_CBC_H

#include <stddef.h>
#include <stdint.h>

#include "aes.h"

typedef enum {
    AES_CBC_SUCCESS = 0,
    AES_CBC_INVALID_ARGUMENT,
    AES_CBC_INVALID_LENGTH,
    AES_CBC_OUTPUT_TOO_SMALL,
    AES_CBC_INVALID_PADDING
} aes_cbc_status;

aes_cbc_status aes_cbc_encrypt_blocks(
    const uint8_t plaintext[],
    size_t plaintext_length,
    const uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t expanded_key[AES_EXPANDED_KEY_SIZE],
    uint8_t ciphertext[],
    size_t ciphertext_capacity
);

aes_cbc_status aes_cbc_decrypt_blocks(
    const uint8_t ciphertext[],
    size_t ciphertext_length,
    const uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t expanded_key[AES_EXPANDED_KEY_SIZE],
    uint8_t plaintext[],
    size_t plaintext_capacity
);

aes_cbc_status aes_cbc_encrypt(
    const uint8_t plaintext[],
    size_t plaintext_length,
    const uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t expanded_key[AES_EXPANDED_KEY_SIZE],
    uint8_t ciphertext[],
    size_t ciphertext_capacity,
    size_t *ciphertext_length
);

aes_cbc_status aes_cbc_decrypt(
    const uint8_t ciphertext[],
    size_t ciphertext_length,
    const uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t expanded_key[AES_EXPANDED_KEY_SIZE],
    uint8_t plaintext[],
    size_t plaintext_capacity,
    size_t *plaintext_length
);

#endif
