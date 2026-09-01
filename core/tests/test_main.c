#include <stdio.h>

int test_fips197(void);
int test_roundtrip(void);

int main(void)
{
    int failures = 0;

    failures += test_fips197();
    failures += test_roundtrip();

    if (failures != 0) {
        puts("AES-128 tests failed.");
        return 1;
    }

    puts("AES-128 tests passed.");
    return 0;
}
