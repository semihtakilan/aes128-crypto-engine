#include "aes_cbc.h"

#include <string.h>

static void secure_zero(uint8_t buffer[], size_t length)
{
    volatile uint8_t *volatile_buffer = buffer;

    for (size_t index = 0U; index < length; index++) {
        volatile_buffer[index] = 0U;
    }
}

static aes_cbc_status validate_block_operation(
    size_t input_length,
    size_t output_capacity,
    const uint8_t input[],
    const uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t expanded_key[AES_EXPANDED_KEY_SIZE],
    uint8_t output[]
)
{
    if (iv == NULL || expanded_key == NULL) {
        return AES_CBC_INVALID_ARGUMENT;
    }
    if ((input_length % AES_BLOCK_SIZE) != 0U) {
        return AES_CBC_INVALID_LENGTH;
    }
    if (input_length > output_capacity) {
        return AES_CBC_OUTPUT_TOO_SMALL;
    }
    if (input_length > 0U && (input == NULL || output == NULL)) {
        return AES_CBC_INVALID_ARGUMENT;
    }

    return AES_CBC_SUCCESS;
}

aes_cbc_status aes_cbc_encrypt_blocks(
    const uint8_t plaintext[],
    size_t plaintext_length,
    const uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t expanded_key[AES_EXPANDED_KEY_SIZE],
    uint8_t ciphertext[],
    size_t ciphertext_capacity
)
{
    const aes_cbc_status validation = validate_block_operation(
        plaintext_length,
        ciphertext_capacity,
        plaintext,
        iv,
        expanded_key,
        ciphertext
    );

    if (validation != AES_CBC_SUCCESS) {
        return validation;
    }

    uint8_t previous_ciphertext[AES_BLOCK_SIZE];
    uint8_t block[AES_BLOCK_SIZE];

    memcpy(previous_ciphertext, iv, AES_BLOCK_SIZE);

    for (size_t offset = 0U; offset < plaintext_length; offset += AES_BLOCK_SIZE) {
        for (uint8_t index = 0U; index < AES_BLOCK_SIZE; index++) {
            block[index] = plaintext[offset + index] ^ previous_ciphertext[index];
        }

        aes_encrypt_block(block, ciphertext + offset, expanded_key);
        memcpy(previous_ciphertext, ciphertext + offset, AES_BLOCK_SIZE);
    }

    secure_zero(previous_ciphertext, AES_BLOCK_SIZE);
    secure_zero(block, AES_BLOCK_SIZE);
    return AES_CBC_SUCCESS;
}

aes_cbc_status aes_cbc_decrypt_blocks(
    const uint8_t ciphertext[],
    size_t ciphertext_length,
    const uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t expanded_key[AES_EXPANDED_KEY_SIZE],
    uint8_t plaintext[],
    size_t plaintext_capacity
)
{
    const aes_cbc_status validation = validate_block_operation(
        ciphertext_length,
        plaintext_capacity,
        ciphertext,
        iv,
        expanded_key,
        plaintext
    );

    if (validation != AES_CBC_SUCCESS) {
        return validation;
    }

    uint8_t previous_ciphertext[AES_BLOCK_SIZE];
    uint8_t ciphertext_block[AES_BLOCK_SIZE];
    uint8_t decrypted_block[AES_BLOCK_SIZE];

    memcpy(previous_ciphertext, iv, AES_BLOCK_SIZE);

    for (size_t offset = 0U; offset < ciphertext_length; offset += AES_BLOCK_SIZE) {
        memcpy(ciphertext_block, ciphertext + offset, AES_BLOCK_SIZE);
        aes_decrypt_block(ciphertext_block, decrypted_block, expanded_key);

        for (uint8_t index = 0U; index < AES_BLOCK_SIZE; index++) {
            decrypted_block[index] ^= previous_ciphertext[index];
        }

        memcpy(plaintext + offset, decrypted_block, AES_BLOCK_SIZE);
        memcpy(previous_ciphertext, ciphertext_block, AES_BLOCK_SIZE);
    }

    secure_zero(previous_ciphertext, AES_BLOCK_SIZE);
    secure_zero(ciphertext_block, AES_BLOCK_SIZE);
    secure_zero(decrypted_block, AES_BLOCK_SIZE);
    return AES_CBC_SUCCESS;
}

static uint8_t valid_padding_mask(const uint8_t last_block[AES_BLOCK_SIZE])
{
    const uint8_t padding_length = last_block[AES_BLOCK_SIZE - 1U];
    const uint32_t zero_difference = (uint32_t)padding_length - 1U;
    const uint32_t too_large_difference =
        (uint32_t)padding_length - (AES_BLOCK_SIZE + 1U);
    const uint8_t is_zero_mask = (uint8_t)((zero_difference >> 8U) & 0xffU);
    const uint8_t is_too_large_mask = (uint8_t)~(
        (uint8_t)((too_large_difference >> 8U) & 0xffU)
    );
    uint8_t invalid_mask = (uint8_t)(is_zero_mask | is_too_large_mask);

    for (uint8_t index = 0U; index < AES_BLOCK_SIZE; index++) {
        const uint32_t difference =
            (uint32_t)padding_length - (uint32_t)(index + 1U);
        const uint8_t selected_mask = (uint8_t)~(
            (uint8_t)((difference >> 8U) & 0xffU)
        );
        const uint8_t padding_difference =
            (uint8_t)(last_block[AES_BLOCK_SIZE - 1U - index] ^ padding_length);

        invalid_mask |= (uint8_t)(selected_mask & padding_difference);
    }

    return (uint8_t)(invalid_mask == 0U);
}

aes_cbc_status aes_cbc_encrypt(
    const uint8_t plaintext[],
    size_t plaintext_length,
    const uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t expanded_key[AES_EXPANDED_KEY_SIZE],
    uint8_t ciphertext[],
    size_t ciphertext_capacity,
    size_t *ciphertext_length
)
{
    if (ciphertext_length == NULL) {
        return AES_CBC_INVALID_ARGUMENT;
    }
    *ciphertext_length = 0U;

    if (iv == NULL || expanded_key == NULL || ciphertext == NULL) {
        return AES_CBC_INVALID_ARGUMENT;
    }
    if (plaintext_length > 0U && plaintext == NULL) {
        return AES_CBC_INVALID_ARGUMENT;
    }

    const size_t padding_length = AES_BLOCK_SIZE - (plaintext_length % AES_BLOCK_SIZE);

    if (ciphertext_capacity < padding_length
        || plaintext_length > ciphertext_capacity - padding_length) {
        return AES_CBC_OUTPUT_TOO_SMALL;
    }

    const size_t padded_length = plaintext_length + padding_length;
    uint8_t previous_ciphertext[AES_BLOCK_SIZE];
    uint8_t block[AES_BLOCK_SIZE];

    memcpy(previous_ciphertext, iv, AES_BLOCK_SIZE);

    for (size_t offset = 0U; offset < padded_length; offset += AES_BLOCK_SIZE) {
        for (uint8_t index = 0U; index < AES_BLOCK_SIZE; index++) {
            const size_t position = offset + index;
            const uint8_t padding_byte = (uint8_t)padding_length;

            block[index] = position < plaintext_length
                ? plaintext[position]
                : padding_byte;
            block[index] ^= previous_ciphertext[index];
        }

        aes_encrypt_block(block, ciphertext + offset, expanded_key);
        memcpy(previous_ciphertext, ciphertext + offset, AES_BLOCK_SIZE);
    }

    secure_zero(previous_ciphertext, AES_BLOCK_SIZE);
    secure_zero(block, AES_BLOCK_SIZE);
    *ciphertext_length = padded_length;
    return AES_CBC_SUCCESS;
}

aes_cbc_status aes_cbc_decrypt(
    const uint8_t ciphertext[],
    size_t ciphertext_length,
    const uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t expanded_key[AES_EXPANDED_KEY_SIZE],
    uint8_t plaintext[],
    size_t plaintext_capacity,
    size_t *plaintext_length
)
{
    if (plaintext_length == NULL) {
        return AES_CBC_INVALID_ARGUMENT;
    }
    *plaintext_length = 0U;

    if (ciphertext_length == 0U || (ciphertext_length % AES_BLOCK_SIZE) != 0U) {
        return AES_CBC_INVALID_LENGTH;
    }
    if (plaintext_capacity < ciphertext_length) {
        return AES_CBC_OUTPUT_TOO_SMALL;
    }

    const aes_cbc_status status = aes_cbc_decrypt_blocks(
        ciphertext,
        ciphertext_length,
        iv,
        expanded_key,
        plaintext,
        plaintext_capacity
    );

    if (status != AES_CBC_SUCCESS) {
        return status;
    }

    const uint8_t *last_block = plaintext + ciphertext_length - AES_BLOCK_SIZE;
    const uint8_t padding_length = last_block[AES_BLOCK_SIZE - 1U];

    if (valid_padding_mask(last_block) == 0U) {
        secure_zero(plaintext, ciphertext_length);
        return AES_CBC_INVALID_PADDING;
    }

    *plaintext_length = ciphertext_length - padding_length;
    return AES_CBC_SUCCESS;
}
