#include <stdio.h>
#include <gmp.h>

int main() {
    mpz_t num;
    mpz_init_set_str(num, "9", 10); // Initialize num with the value 9 (1001 in binary)
    
    // Test the 0th, 1st, 2nd, and 3rd bits
    printf("Bit at index 0: %d\n", mpz_tstbit(num, 0));
    mpz_clrbit (num,3);
    gmp_printf("NUM %Zd\n",num);
    printf("Bit at index 1: %d\n", mpz_tstbit(num, 1));
    printf("Bit at index 2: %d\n", mpz_tstbit(num, 2));
    printf("Bit at index 3: %d\n", mpz_tstbit(num, 3));

    mpz_clear(num); // Clean up
    
    return 0;
}

