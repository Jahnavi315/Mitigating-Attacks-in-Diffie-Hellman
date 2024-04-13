#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>

void find_primitive_root(mpz_t p) {
    mpz_t q, a, i,rem, all_ones;
    mpz_inits(q, a,i, rem, all_ones, NULL);

    mpz_sub_ui(q, p, 1); // q = p - 1

    // Calculate the value with all bits set to 1

    mpz_set_ui(a, 2); // Start with a = 2

    while (mpz_cmp(a, q) <= 0) { // While a <= p-1
        int is_PR = 1; // Initialize is_PR to 1
        
     //   mpz_init2(all_ones, 2 * mpz_sizeinbase(p, 2)); 	
	mpz_set_ui(all_ones, 2);
	mpz_pow_ui(all_ones, all_ones, mpz_get_ui(p)); // all_ones = 2^(p)

	mpz_sub_ui(all_ones, all_ones, 1); // all_ones = 2^(p) - 1
	//gmp_printf("all ones at start of a %Zd : %ZX\n", a, all_ones);
    
        // Loop from i to p-1
        mpz_set_ui(i, 1);	
        while( mpz_cmp(i, q) <= 0)  {
        //printf("started loop\n");
        
	    mpz_powm(rem, a, i, p); // power = a^i mod p
	    // Check if the i-th bit is set in all_ones
	    if (mpz_tstbit(all_ones,mpz_get_ui(rem)) == 1) {
	    	mpz_clrbit (all_ones,mpz_get_ui(rem));
	    	//gmp_printf("bit was set!,all ones now: %ZX and rem %Zd\n",all_ones,rem);
	    }else{
	   	//gmp_printf("all ones now: %ZX , rem %Zd\n",all_ones,rem);
	   	is_PR = 0;
	   	break; 	
	    }
	    //gmp_printf("%ZX %Zd rem = %Zd\n",all_ones,i, rem);
	    mpz_add_ui(i, i, 1);
	    //printf("loop");
	}

        if (is_PR) {
            gmp_printf("Primitive root (q) = %Zd\n", a);
            //break; // Exit the loop since primitive root found
        }

        mpz_add_ui(a, a, 1); // Increment 'a'
    }

    mpz_clears(q, a, rem, all_ones, NULL);
}

int main() {
    mpz_t prime;
    gmp_randstate_t state;
    gmp_randinit_default(state);

    // Generate a 2048-bit prime number
    mpz_init(prime);
    mpz_urandomb(prime, state, 32);
    mpz_nextprime(prime, prime);
    gmp_printf("Generated Prime (p) = %Zd\n", prime);

    // Find the primitive root
    find_primitive_root(prime);

    mpz_clear(prime);
    gmp_randclear(state);

    return 0;
}

