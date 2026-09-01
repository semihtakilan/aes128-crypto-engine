#include "aes.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

int test_secure_zero(void)
{
    uint8_t buffer[1024];

    memset(buffer, 0xa5, sizeof(buffer));
    aes_secure_zero(buffer, sizeof(buffer));

    for (size_t index = 0U; index < sizeof(buffer); index++) {
        if (buffer[index] != 0U) {
            printf("FAIL: secure zero at byte %zu\n", index);
            return 1;
        }
    }

    return 0;
}
