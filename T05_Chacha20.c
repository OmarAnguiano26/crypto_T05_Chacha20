/**
 * Chacha20
*/

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Define the ChaCha20 constants
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define QUARTER_ROUND(a, b, c, d) \
    a += b; d ^= a; d = ROTATE_LEFT(d, 16); \
    c += d; b ^= c; b = ROTATE_LEFT(b, 12); \
    a += b; d ^= a; d = ROTATE_LEFT(d, 8); \
    c += d; b ^= c; b = ROTATE_LEFT(b, 7);

// ChaCha20 encryption function
void chacha20_block(uint32_t state[16]) 
{
    int i;
    uint32_t x[16];

    // Copy the state to a working buffer
    memcpy(x, state, sizeof(uint32_t) * 16);

    // Perform 10 rounds of ChaCha20 quarter rounds
    for (i = 0; i < 10; ++i) {
        QUARTER_ROUND(x[0], x[4], x[8], x[12])
        QUARTER_ROUND(x[1], x[5], x[9], x[13])
        QUARTER_ROUND(x[2], x[6], x[10], x[14])
        QUARTER_ROUND(x[3], x[7], x[11], x[15])
        QUARTER_ROUND(x[0], x[5], x[10], x[15])
        QUARTER_ROUND(x[1], x[6], x[11], x[12])
        QUARTER_ROUND(x[2], x[7], x[8], x[13])
        QUARTER_ROUND(x[3], x[4], x[9], x[14])
    }

    // Add the original state to the ChaCha20 block
    for (i = 0; i < 16; ++i) {
        state[i] += x[i];
    }
}

// ChaCha20 key setup function
void chacha20_keysetup(uint32_t state[16], const uint8_t *key) 
{
    // Constants for ChaCha20
    static const char sigma[16] = "expand 32-byte k";
    int i;

    // Initialize the ChaCha20 state
    state[0] = 0x61707865; // "expa"
    state[1] = 0x3320646e; // "nd 3"
    state[2] = 0x79622d32; // "2-by"
    state[3] = 0x6b206574; // "te k"

    // Copy the key into the state
    for (i = 0; i < 8; ++i) {
        state[4 + i] = ((uint32_t *)key)[i];
    }
}

// ChaCha20 nonce setup function
void chacha20_nonce_setup(uint32_t state[16], const uint8_t *nonce) 
{
    // Copy the nonce into the state
    state[12] = 0;
    state[13] = 0;
    state[14] = ((uint32_t *)nonce)[0];
    state[15] = ((uint32_t *)nonce)[1];
}

// ChaCha20 encryption/decryption function
void chacha20_encrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *input, uint8_t *output, size_t size) 
{
    uint32_t state[16];
    size_t i;

    // Setup the ChaCha20 key and nonce
    chacha20_keysetup(state, key);
    chacha20_nonce_setup(state, nonce);

    // Process each block of the input
    for (i = 0; i < size; i += 64) {
        // Generate the next ChaCha20 block
        chacha20_block(state);

        // XOR the input with the ChaCha20 block to produce the output
        for (size_t j = 0; j < 64 && i + j < size; ++j) {
            output[i + j] = input[i + j] ^ ((uint8_t *)state)[j];
        }

        // Increment the block counter in the ChaCha20 state
        ++state[12];
        if (state[12] == 0) {
            ++state[13];
        }
    }
}

int main()
{
    uint8_t key[32] = {0}; // Should be a 256-bit (32-byte) key
    uint8_t nonce[8] = {0}; // Should be a 64-bit (8-byte) nonce

    // Define a message to be encrypted
    char message[] = "Hello, ChaCha20!";
    uint8_t *encrypted_message = malloc(strlen(message));
    char *decrypted_message = malloc(strlen(message) + 1);
    // Encrypt the message
    chacha20_encrypt(key, nonce, (uint8_t *)message, encrypted_message, strlen(message));

    // Decrypt the message
    chacha20_encrypt(key, nonce, encrypted_message, (uint8_t *)decrypted_message, strlen(message));

    // Null-terminate the decrypted message
    decrypted_message[strlen(message)] = '\0';

    // Print the encrypted and decrypted messages
    printf("Original message: %s\n", message);
    printf("Encrypted message (hex): ");
    for (size_t i = 0; i < strlen(message); ++i) 
    {
        printf("%02x", encrypted_message[i]);
    }
    printf("\nDecrypted message: %s\n", decrypted_message);

    printf("Hola\n");

     // Free allocated memory
    free(encrypted_message);
    free(decrypted_message);
    return 0;
}