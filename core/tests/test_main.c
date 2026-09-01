#include <stdio.h>

int test_fips197(void);

int main(void)
{
    const int failures = test_fips197();

    if (failures != 0) {
        puts("AES-128 tests failed.");
        return 1;
    }

    puts("AES-128 tests passed.");
    return 0;
}
