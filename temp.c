#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

#define HASH_LENGTH 32 // SHA-256 produces a 32-byte hash

// Function to compute SHA-256 hash
void computeSHA256(const unsigned char input[], size_t input_len, unsigned char output[]) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, input, input_len);
    SHA256_Final(output, &ctx);
}

// Function to print hash value
void printHash(const unsigned char hash[], size_t hash_len) {
    for (size_t i = 0; i < hash_len; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int main() {
    // Input array
    unsigned char input[] = "Hello, world!";
    size_t input_len = strlen((const char*)input);

    // Output array to store hash
    unsigned char hash[HASH_LENGTH];

    // Compute SHA-256 hash
    computeSHA256(input, input_len, hash);

    // Print hash value
    printf("SHA-256 hash: ");
    printHash(hash, HASH_LENGTH);

    return 0;
}

