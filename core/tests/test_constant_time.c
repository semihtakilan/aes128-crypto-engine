#include "aes.h"

#include <stdio.h>
#include <string.h>

int test_constant_time_compare(void)
{
    static const uint8_t expected[32] = {
        0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U,
        0x88U, 0x99U, 0xaaU, 0xbbU, 0xccU, 0xddU, 0xeeU, 0xffU,
        0x10U, 0x21U, 0x32U, 0x43U, 0x54U, 0x65U, 0x76U, 0x87U,
        0x98U, 0xa9U, 0xbaU, 0xcbU, 0xdcU, 0xedU, 0xfeU, 0x0fU
    };
    uint8_t candidate[sizeof(expected)];

    memcpy(candidate, expected, sizeof(candidate));
    if (aes_constant_time_equal(expected, candidate, sizeof(expected)) == 0U
        || aes_constant_time_equal(expected, candidate, 0U) == 0U) {
        puts("FAIL: equal constant-time comparison");
        return 1;
    }

    for (size_t index = 0U; index < sizeof(candidate); index++) {
        candidate[index] ^= 0x01U;
        if (aes_constant_time_equal(expected, candidate, sizeof(expected)) != 0U) {
            printf("FAIL: modified constant-time comparison at byte %zu\n", index);
            return 1;
        }
        candidate[index] = expected[index];
    }

    return 0;
}
