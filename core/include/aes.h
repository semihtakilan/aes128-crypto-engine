#ifndef AES_H
#define AES_H

#include <stdint.h>

#define AES_BLOCK_SIZE 16U
#define AES_128_KEY_SIZE 16U
#define AES_ROUND_COUNT 10U
#define AES_EXPANDED_KEY_SIZE (AES_BLOCK_SIZE * (AES_ROUND_COUNT + 1U))

void aes_expand_key(
    const uint8_t key[AES_128_KEY_SIZE],
    uint8_t expanded_key[AES_EXPANDED_KEY_SIZE]
);

void aes_encrypt_block(
    const uint8_t input[AES_BLOCK_SIZE],
    uint8_t output[AES_BLOCK_SIZE],
    const uint8_t expanded_key[AES_EXPANDED_KEY_SIZE]
);

#endif
