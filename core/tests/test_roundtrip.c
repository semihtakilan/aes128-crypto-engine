#include "aes.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint8_t next_test_byte(uint32_t *state)
{
    *state = (*state * 1664525U) + 1013904223U;
    return (uint8_t)(*state >> 24U);
}

int test_roundtrip(void)
{
    uint32_t generator_state = 0x12345678U;

    for (unsigned int test_case = 0U; test_case < 256U; test_case++) {
        uint8_t key[AES_128_KEY_SIZE];
        uint8_t plaintext[AES_BLOCK_SIZE];
        uint8_t ciphertext[AES_BLOCK_SIZE];
        uint8_t decrypted[AES_BLOCK_SIZE];
        uint8_t in_place[AES_BLOCK_SIZE];
        uint8_t expanded_key[AES_EXPANDED_KEY_SIZE];

        for (unsigned int index = 0U; index < AES_128_KEY_SIZE; index++) {
            key[index] = next_test_byte(&generator_state);
        }
        for (unsigned int index = 0U; index < AES_BLOCK_SIZE; index++) {
            plaintext[index] = next_test_byte(&generator_state);
        }

        aes_expand_key(key, expanded_key);
        aes_encrypt_block(plaintext, ciphertext, expanded_key);
        aes_decrypt_block(ciphertext, decrypted, expanded_key);

        if (memcmp(plaintext, decrypted, AES_BLOCK_SIZE) != 0) {
            printf("FAIL: block round-trip case %u\n", test_case);
            return 1;
        }

        memcpy(in_place, plaintext, AES_BLOCK_SIZE);
        aes_encrypt_block(in_place, in_place, expanded_key);
        aes_decrypt_block(in_place, in_place, expanded_key);

        if (memcmp(plaintext, in_place, AES_BLOCK_SIZE) != 0) {
            printf("FAIL: in-place round-trip case %u\n", test_case);
            return 1;
        }
    }

    return 0;
}
