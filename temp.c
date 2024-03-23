#include <stdio.h>
#include <gmp.h>

int main() {
    mpz_t num;
    mpz_init_set_ui(num, 255); // Initialize num with the value 10

    // Calculate the size of the number in base 16 (hexadecimal)
    size_t size_hex = mpz_sizeinbase(num, 16);

    // Calculate the size of the number in base 2 (binary)
    size_t size_bin = mpz_sizeinbase(num, 2);

    size_t size_dec = mpz_sizeinbase(num, 10);
    // Print the sizes
    printf("Size of the number in hexadecimal (base 16): %zu\n", size_hex);
    printf("Size of the number in binary (base 2): %zu\n", size_bin);
printf("Size of the number in dec (base 10): %zu\n", size_dec);
    // Clean up
    mpz_clear(num);

    return 0;
}

