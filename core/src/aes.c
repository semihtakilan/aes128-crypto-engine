#include "aes.h"

#include "aes_tables.h"

typedef uint8_t aes_state[4][4];

static void secure_zero(uint8_t buffer[], uint8_t length)
{
    volatile uint8_t *volatile_buffer = buffer;

    for (uint8_t index = 0U; index < length; index++) {
        volatile_buffer[index] = 0U;
    }
}

static uint8_t xtime(uint8_t value)
{
    const uint8_t reduction = (uint8_t)(0x1bU & (uint8_t)-(value >> 7U));

    return (uint8_t)((value << 1U) ^ reduction);
}

static uint8_t gf_multiply(uint8_t left, uint8_t right)
{
    uint8_t result = 0U;
    uint8_t multiplier = right;

    for (uint8_t bit = 0U; bit < 8U; bit++) {
        const uint8_t mask = (uint8_t)-(multiplier & 1U);

        result ^= (uint8_t)(left & mask);
        left = xtime(left);
        multiplier >>= 1U;
    }

    return result;
}

static void rotate_word_left(uint8_t word[4])
{
    const uint8_t first = word[0];

    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = first;
}

static void substitute_word(uint8_t word[4])
{
    for (uint8_t index = 0U; index < 4U; index++) {
        word[index] = aes_substitute_byte(word[index]);
    }
}

void aes_expand_key(
    const uint8_t key[AES_128_KEY_SIZE],
    uint8_t expanded_key[AES_EXPANDED_KEY_SIZE]
)
{
    for (uint8_t index = 0U; index < AES_128_KEY_SIZE; index++) {
        expanded_key[index] = key[index];
    }

    uint8_t bytes_generated = AES_128_KEY_SIZE;
    uint8_t round = 1U;

    while (bytes_generated < AES_EXPANDED_KEY_SIZE) {
        uint8_t word[4];

        for (uint8_t index = 0U; index < 4U; index++) {
            word[index] = expanded_key[bytes_generated - 4U + index];
        }

        if ((bytes_generated % AES_128_KEY_SIZE) == 0U) {
            rotate_word_left(word);
            substitute_word(word);
            word[0] ^= aes_round_constant(round);
            round++;
        }

        for (uint8_t index = 0U; index < 4U; index++) {
            expanded_key[bytes_generated] =
                expanded_key[bytes_generated - AES_128_KEY_SIZE] ^ word[index];
            bytes_generated++;
        }

        secure_zero(word, 4U);
    }
}

static void load_state(const uint8_t input[AES_BLOCK_SIZE], aes_state state)
{
    for (uint8_t column = 0U; column < 4U; column++) {
        for (uint8_t row = 0U; row < 4U; row++) {
            state[row][column] = input[(column * 4U) + row];
        }
    }
}

static void store_state(const aes_state state, uint8_t output[AES_BLOCK_SIZE])
{
    for (uint8_t column = 0U; column < 4U; column++) {
        for (uint8_t row = 0U; row < 4U; row++) {
            output[(column * 4U) + row] = state[row][column];
        }
    }
}

static void add_round_key(aes_state state, const uint8_t expanded_key[], uint8_t round)
{
    const uint8_t round_offset = (uint8_t)(round * AES_BLOCK_SIZE);

    for (uint8_t column = 0U; column < 4U; column++) {
        for (uint8_t row = 0U; row < 4U; row++) {
            state[row][column] ^= expanded_key[round_offset + (column * 4U) + row];
        }
    }
}

static void substitute_bytes(aes_state state)
{
    for (uint8_t row = 0U; row < 4U; row++) {
        for (uint8_t column = 0U; column < 4U; column++) {
            state[row][column] = aes_substitute_byte(state[row][column]);
        }
    }
}

static void shift_rows(aes_state state)
{
    for (uint8_t row = 1U; row < 4U; row++) {
        uint8_t shifted_row[4];

        for (uint8_t column = 0U; column < 4U; column++) {
            shifted_row[column] = state[row][(column + row) % 4U];
        }

        for (uint8_t column = 0U; column < 4U; column++) {
            state[row][column] = shifted_row[column];
        }
    }
}

static void mix_columns(aes_state state)
{
    for (uint8_t column = 0U; column < 4U; column++) {
        const uint8_t first = state[0][column];
        const uint8_t second = state[1][column];
        const uint8_t third = state[2][column];
        const uint8_t fourth = state[3][column];

        state[0][column] =
            gf_multiply(first, 0x02U) ^ gf_multiply(second, 0x03U) ^ third ^ fourth;
        state[1][column] =
            first ^ gf_multiply(second, 0x02U) ^ gf_multiply(third, 0x03U) ^ fourth;
        state[2][column] =
            first ^ second ^ gf_multiply(third, 0x02U) ^ gf_multiply(fourth, 0x03U);
        state[3][column] =
            gf_multiply(first, 0x03U) ^ second ^ third ^ gf_multiply(fourth, 0x02U);
    }
}

static void inverse_substitute_bytes(aes_state state)
{
    for (uint8_t row = 0U; row < 4U; row++) {
        for (uint8_t column = 0U; column < 4U; column++) {
            state[row][column] = aes_inverse_substitute_byte(state[row][column]);
        }
    }
}

static void inverse_shift_rows(aes_state state)
{
    for (uint8_t row = 1U; row < 4U; row++) {
        uint8_t shifted_row[4];

        for (uint8_t column = 0U; column < 4U; column++) {
            shifted_row[column] = state[row][(column + 4U - row) % 4U];
        }

        for (uint8_t column = 0U; column < 4U; column++) {
            state[row][column] = shifted_row[column];
        }
    }
}

static void inverse_mix_columns(aes_state state)
{
    for (uint8_t column = 0U; column < 4U; column++) {
        const uint8_t first = state[0][column];
        const uint8_t second = state[1][column];
        const uint8_t third = state[2][column];
        const uint8_t fourth = state[3][column];

        state[0][column] =
            gf_multiply(first, 0x0eU) ^ gf_multiply(second, 0x0bU)
            ^ gf_multiply(third, 0x0dU) ^ gf_multiply(fourth, 0x09U);
        state[1][column] =
            gf_multiply(first, 0x09U) ^ gf_multiply(second, 0x0eU)
            ^ gf_multiply(third, 0x0bU) ^ gf_multiply(fourth, 0x0dU);
        state[2][column] =
            gf_multiply(first, 0x0dU) ^ gf_multiply(second, 0x09U)
            ^ gf_multiply(third, 0x0eU) ^ gf_multiply(fourth, 0x0bU);
        state[3][column] =
            gf_multiply(first, 0x0bU) ^ gf_multiply(second, 0x0dU)
            ^ gf_multiply(third, 0x09U) ^ gf_multiply(fourth, 0x0eU);
    }
}

void aes_encrypt_block(
    const uint8_t input[AES_BLOCK_SIZE],
    uint8_t output[AES_BLOCK_SIZE],
    const uint8_t expanded_key[AES_EXPANDED_KEY_SIZE]
)
{
    aes_state state;

    load_state(input, state);
    add_round_key(state, expanded_key, 0U);

    for (uint8_t round = 1U; round < AES_ROUND_COUNT; round++) {
        substitute_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, expanded_key, round);
    }

    substitute_bytes(state);
    shift_rows(state);
    add_round_key(state, expanded_key, AES_ROUND_COUNT);
    store_state(state, output);
    secure_zero((uint8_t *)state, (uint8_t)sizeof(state));
}

void aes_decrypt_block(
    const uint8_t input[AES_BLOCK_SIZE],
    uint8_t output[AES_BLOCK_SIZE],
    const uint8_t expanded_key[AES_EXPANDED_KEY_SIZE]
)
{
    aes_state state;

    load_state(input, state);
    add_round_key(state, expanded_key, AES_ROUND_COUNT);

    for (uint8_t round = AES_ROUND_COUNT - 1U; round > 0U; round--) {
        inverse_shift_rows(state);
        inverse_substitute_bytes(state);
        add_round_key(state, expanded_key, round);
        inverse_mix_columns(state);
    }

    inverse_shift_rows(state);
    inverse_substitute_bytes(state);
    add_round_key(state, expanded_key, 0U);
    store_state(state, output);
    secure_zero((uint8_t *)state, (uint8_t)sizeof(state));
}
