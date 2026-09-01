#ifndef AES_TABLES_H
#define AES_TABLES_H

#include <stdint.h>

uint8_t aes_substitute_byte(uint8_t value);
uint8_t aes_inverse_substitute_byte(uint8_t value);
uint8_t aes_round_constant(uint8_t round);

#endif
