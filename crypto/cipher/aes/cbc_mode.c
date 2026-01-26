#include "cbc_mode.h"

bool ll_AES_CBC_Encrypt(
    const AES_KEY *key,
    uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out) {
    if (!key || !iv || !in || !out || (in_len % AES_BLOCK_SIZE) != 0) return false;

    // Split IV into two 64-bit words
    uint64_t c0 = AES_LOAD64(iv);
    uint64_t c1 = AES_LOAD64(iv + 8);

    for (size_t i = 0; i < in_len; i += AES_BLOCK_SIZE) {
        // Load plaintext block
        uint64_t p0 = AES_LOAD64(in + i);
        uint64_t p1 = AES_LOAD64(in + i + 8);

        // XOR with previous ciphertext (CBC step)
        uint64_t x0 = p0 ^ c0;
        uint64_t x1 = p1 ^ c1;

        // Pack x0/x1 into a temporary block
        uint8_t block[AES_BLOCK_SIZE];
        AES_STORE64(block, x0);
        AES_STORE64(block + 8, x1);

        // Encrypt the block
        if (!ll_AES_EncryptBlock(key, block, out + i)) return false;

        // Update c0/c1 for next round
        c0 = AES_LOAD64(out + i);
        c1 = AES_LOAD64(out + i + 8);
    }

    return true;
}

bool ll_AES_CBC_Decrypt(
    const AES_KEY *key,
    uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out) {
    if (!key || !iv || !in || !out || (in_len % AES_BLOCK_SIZE) != 0) return false;

    uint64_t prev0 = AES_LOAD64(iv);     // first 8 bytes of IV
    uint64_t prev1 = AES_LOAD64(iv + 8); // last 8 bytes of IV

    uint8_t block[AES_BLOCK_SIZE] = {0}; // temporary decrypted block

    for (size_t i = 0; i < in_len; i += AES_BLOCK_SIZE) {
        // Decrypt ciphertext block into temporary buffer
        if (!ll_AES_DecryptBlock(key, in + i, block)) return false;

        // Load decrypted block as two 64-bit words
        uint64_t x0 = AES_LOAD64(block);
        uint64_t x1 = AES_LOAD64(block + 8);

        // XOR with previous ciphertext (CBC step)
        x0 ^= prev0;
        x1 ^= prev1;

        // Store result to output
        AES_STORE64(out + i, x0);
        AES_STORE64(out + i + 8, x1);

        // Update prev for next block
        prev0 = AES_LOAD64(in + i);
        prev1 = AES_LOAD64(in + i + 8);
    }

    SECURE_ZERO(block, sizeof(block));

    return true;
}
