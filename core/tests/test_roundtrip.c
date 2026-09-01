#include "aes_cbc.h"

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

    uint8_t cbc_key[AES_128_KEY_SIZE];
    uint8_t iv[AES_BLOCK_SIZE];
    uint8_t plaintext[1024];
    uint8_t ciphertext[1024];
    uint8_t decrypted[1024];
    uint8_t in_place[1024];
    uint8_t expanded_key[AES_EXPANDED_KEY_SIZE];

    for (unsigned int index = 0U; index < AES_128_KEY_SIZE; index++) {
        cbc_key[index] = next_test_byte(&generator_state);
    }
    for (unsigned int index = 0U; index < AES_BLOCK_SIZE; index++) {
        iv[index] = next_test_byte(&generator_state);
    }
    aes_expand_key(cbc_key, expanded_key);

    for (size_t plaintext_length = 0U; plaintext_length <= 1000U; plaintext_length++) {
        for (size_t index = 0U; index < plaintext_length; index++) {
            plaintext[index] = next_test_byte(&generator_state);
        }

        size_t ciphertext_length = 0U;
        const aes_cbc_status encryption_status = aes_cbc_encrypt(
            plaintext,
            plaintext_length,
            iv,
            expanded_key,
            ciphertext,
            sizeof(ciphertext),
            &ciphertext_length
        );
        if (encryption_status != AES_CBC_SUCCESS) {
            printf("FAIL: CBC encryption length %zu\n", plaintext_length);
            return 1;
        }

        size_t decrypted_length = 0U;
        const aes_cbc_status decryption_status = aes_cbc_decrypt(
            ciphertext,
            ciphertext_length,
            iv,
            expanded_key,
            decrypted,
            sizeof(decrypted),
            &decrypted_length
        );
        if (decryption_status != AES_CBC_SUCCESS
            || decrypted_length != plaintext_length
            || memcmp(plaintext, decrypted, plaintext_length) != 0) {
            printf("FAIL: CBC round-trip length %zu\n", plaintext_length);
            return 1;
        }

        memcpy(in_place, plaintext, plaintext_length);
        size_t in_place_ciphertext_length = 0U;
        if (aes_cbc_encrypt(
                in_place,
                plaintext_length,
                iv,
                expanded_key,
                in_place,
                sizeof(in_place),
                &in_place_ciphertext_length
            ) != AES_CBC_SUCCESS) {
            printf("FAIL: in-place CBC encryption length %zu\n", plaintext_length);
            return 1;
        }

        size_t in_place_plaintext_length = 0U;
        if (aes_cbc_decrypt(
                in_place,
                in_place_ciphertext_length,
                iv,
                expanded_key,
                in_place,
                sizeof(in_place),
                &in_place_plaintext_length
            ) != AES_CBC_SUCCESS
            || in_place_plaintext_length != plaintext_length
            || memcmp(plaintext, in_place, plaintext_length) != 0) {
            printf("FAIL: in-place CBC round-trip length %zu\n", plaintext_length);
            return 1;
        }
    }

    return 0;
}
