#include "aes_cbc.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int test_padding_case(
    size_t plaintext_length,
    const uint8_t key[AES_128_KEY_SIZE],
    const uint8_t iv[AES_BLOCK_SIZE]
)
{
    uint8_t plaintext[17];
    uint8_t ciphertext[32];
    uint8_t padded_plaintext[32];
    uint8_t decrypted[32];
    uint8_t expanded_key[AES_EXPANDED_KEY_SIZE];
    const uint8_t expected_padding =
        (uint8_t)(AES_BLOCK_SIZE - (plaintext_length % AES_BLOCK_SIZE));
    const size_t expected_ciphertext_length = plaintext_length + expected_padding;

    for (size_t index = 0U; index < sizeof(plaintext); index++) {
        plaintext[index] = (uint8_t)(index + 1U);
    }

    aes_expand_key(key, expanded_key);

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
    if (encryption_status != AES_CBC_SUCCESS
        || ciphertext_length != expected_ciphertext_length) {
        printf("FAIL: PKCS#7 encryption length for %zu bytes\n", plaintext_length);
        return 1;
    }

    const aes_cbc_status raw_decryption_status = aes_cbc_decrypt_blocks(
        ciphertext,
        ciphertext_length,
        iv,
        expanded_key,
        padded_plaintext,
        sizeof(padded_plaintext)
    );
    if (raw_decryption_status != AES_CBC_SUCCESS) {
        printf("FAIL: raw padded decryption for %zu bytes\n", plaintext_length);
        return 1;
    }
    for (size_t index = plaintext_length; index < ciphertext_length; index++) {
        if (padded_plaintext[index] != expected_padding) {
            printf("FAIL: PKCS#7 byte value for %zu bytes\n", plaintext_length);
            return 1;
        }
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
        || memcmp(decrypted, plaintext, plaintext_length) != 0) {
        printf("FAIL: PKCS#7 round-trip for %zu bytes\n", plaintext_length);
        return 1;
    }

    return 0;
}

int test_padding(void)
{
    static const uint8_t key[AES_128_KEY_SIZE] = {
        0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0aU, 0x0bU, 0x0cU, 0x0dU, 0x0eU, 0x0fU
    };
    static const uint8_t iv[AES_BLOCK_SIZE] = {
        0x0fU, 0x0eU, 0x0dU, 0x0cU, 0x0bU, 0x0aU, 0x09U, 0x08U,
        0x07U, 0x06U, 0x05U, 0x04U, 0x03U, 0x02U, 0x01U, 0x00U
    };
    static const size_t boundary_lengths[] = { 0U, 1U, 15U, 16U, 17U };

    int failures = 0;
    for (size_t index = 0U; index < sizeof(boundary_lengths) / sizeof(boundary_lengths[0]); index++) {
        failures += test_padding_case(boundary_lengths[index], key, iv);
    }

    uint8_t expanded_key[AES_EXPANDED_KEY_SIZE];
    uint8_t invalid_padded_plaintext[AES_BLOCK_SIZE];
    uint8_t invalid_ciphertext[AES_BLOCK_SIZE];
    uint8_t invalid_plaintext[AES_BLOCK_SIZE];

    aes_expand_key(key, expanded_key);
    memset(invalid_padded_plaintext, 0x10, sizeof(invalid_padded_plaintext));
    invalid_padded_plaintext[AES_BLOCK_SIZE - 1U] = 0x00U;
    if (aes_cbc_encrypt_blocks(
            invalid_padded_plaintext,
            sizeof(invalid_padded_plaintext),
            iv,
            expanded_key,
            invalid_ciphertext,
            sizeof(invalid_ciphertext)
        ) != AES_CBC_SUCCESS) {
        puts("FAIL: invalid padding fixture encryption");
        failures++;
    } else {
        memset(invalid_plaintext, 0xa5, sizeof(invalid_plaintext));
        size_t invalid_plaintext_length = 0U;
        const aes_cbc_status status = aes_cbc_decrypt(
            invalid_ciphertext,
            sizeof(invalid_ciphertext),
            iv,
            expanded_key,
            invalid_plaintext,
            sizeof(invalid_plaintext),
            &invalid_plaintext_length
        );
        uint8_t zeroes[AES_BLOCK_SIZE] = { 0U };

        if (status != AES_CBC_INVALID_PADDING
            || invalid_plaintext_length != 0U
            || memcmp(invalid_plaintext, zeroes, sizeof(zeroes)) != 0) {
            puts("FAIL: invalid padding rejection");
            failures++;
        }
    }

    return failures;
}
