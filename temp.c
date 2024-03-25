#include <stdio.h>
#include <gmp.h>

void find_primitive_root(mpz_t p) {
    mpz_t q, a, p_minus_one, power;
    mpz_inits(q, a, p_minus_one, power, NULL);

    mpz_sub_ui(p_minus_one, p, 1); // p_minus_one = p - 1
    mpz_set(q, p_minus_one); // q = p - 1

    // Try different values of 'a' until we find a primitive root
    mpz_set_ui(a, 2); // Start with a = 2
    while (1) {
        mpz_powm(power, a, q, p); // power = a^q mod p

        // If a^q ≢ 1 (mod p), then 'a' is a primitive root
        if (mpz_cmp_ui(power, 1) != 0) {
            gmp_printf("Primitive Root (q) = %Zd\n", a);
            break;
        }
	
	gmp_printf("Checked %Zd\n", a);
	
        mpz_add_ui(a, a, 1); // Increment 'a'
        
    }

    mpz_clears(q, a, p_minus_one, power, NULL);
}

int main() {
    mpz_t prime;
    gmp_randstate_t state;
    gmp_randinit_default(state);

    // Generate a 2048-bit prime number
    mpz_init(prime);
    mpz_urandomb(prime, state, 8);
    mpz_nextprime(prime, prime);

    gmp_printf("Generated Prime (p) = %Zd\n", prime);

    // Find the primitive root
    find_primitive_root(prime);

    mpz_clear(prime);
    gmp_randclear(state);

    return 0;
}

