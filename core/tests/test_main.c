#include <stdio.h>

int test_fips197(void);
int test_roundtrip(void);
int test_sp800_38a(void);
int test_padding(void);
int test_constant_time_compare(void);

int main(void)
{
    int failures = 0;

    failures += test_fips197();
    failures += test_roundtrip();
    failures += test_sp800_38a();
    failures += test_padding();
    failures += test_constant_time_compare();

    if (failures != 0) {
        puts("AES-128 tests failed.");
        return 1;
    }

    puts("AES-128 tests passed.");
    return 0;
}
