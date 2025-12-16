#include "cbc_mode.h"

bool ll_AES_CBC_Encrypt(const AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len, uint8_t *out) {
    if (!key || !iv || !in || (in_len % AES_BLOCK_SIZE) != 0 || !out) return false; 

    uint8_t x[AES_BLOCK_SIZE];

    for (size_t i = 0; i < in_len; i += AES_BLOCK_SIZE) {
        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            // XOR with previous ciphertext block (or IV for first block)
            x[j] = in[i + (size_t)j] ^ (i == 0 ? iv[j] : out[i - AES_BLOCK_SIZE + (size_t)j]);
        }

        // Encrypt current ciphertext block
        if (!ll_AES_EncryptBlock(key, x, out + i)) return false;
    }

    return true;
}

bool ll_AES_CBC_Decrypt(const AES_KEY *key, uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len, uint8_t *out) {
    if (!key || !iv || !in || (in_len % AES_BLOCK_SIZE) != 0 || !out) return false; 

    uint8_t x[AES_BLOCK_SIZE];      // temporary buffer for decrypted block
    uint8_t prev[AES_BLOCK_SIZE];   // previous ciphertext (or IV)

    SECURE_MEMCPY(prev, iv, AES_BLOCK_SIZE);

    for (size_t i = 0; i < in_len; i += AES_BLOCK_SIZE) {
        // Decrypt current ciphertext block
        if (!ll_AES_DecryptBlock(key, in + i, x)) return false;

        // XOR with previous ciphertext block (or IV for first block)
        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            out[i + (size_t)j] = x[j] ^ prev[j];
        }

        // Update prev for next block
        SECURE_MEMCPY(prev, in + i, AES_BLOCK_SIZE);
    }

    return true;
}
