/*
 * CryptoForge - cbc_mode.c / AES-CBC Implementation
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against WyChaProof test vectors. No hardware optimizations. Use with caution.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#include "../../../include/crypto/cbc_mode.h"

bool ll_AES_CBC_Encrypt(
    const ll_AES_KEY *key,
    uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out) {
    if (!key || !iv || !in || !out || (in_len % AES_BLOCK_SIZE) != 0) return false;

    bool ok = false;

    uint8_t prev[AES_BLOCK_SIZE] = {0};
    SECURE_MEMCPY(prev, iv, AES_BLOCK_SIZE);

    uint8_t block[AES_BLOCK_SIZE]; // temporary encrypt block

    for (size_t i = 0; i < in_len; i += AES_BLOCK_SIZE) {
        // XOR with previous ciphertext (CBC step)
        for (size_t j = 0; j < AES_BLOCK_SIZE; j++)
            block[j] = in[i + j] ^ prev[j];

        // Encrypt the block
        if (!ll_AES_EncryptBlock(key, block, out + i)) goto cleanup;
        
        // Update prev to current ciphertext
        SECURE_MEMCPY(prev, out + i, AES_BLOCK_SIZE);
    }

    ok = true;

cleanup:
    SECURE_ZERO(prev, sizeof(prev));
    SECURE_ZERO(block, sizeof(block));

    return ok;
}

bool ll_AES_CBC_Decrypt(
    const ll_AES_KEY *key,
    uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out) {
    if (!key || !iv || !in || !out || (in_len % AES_BLOCK_SIZE) != 0) return false;

    bool ok = false;

    uint8_t prev[AES_BLOCK_SIZE] = {0};
    SECURE_MEMCPY(prev, iv, AES_BLOCK_SIZE);

    uint8_t block[AES_BLOCK_SIZE] = {0}; // temporary decrypted block

    for (size_t i = 0; i < in_len; i += AES_BLOCK_SIZE) {
        // Decrypt ciphertext block into temporary buffer
        if (!ll_AES_DecryptBlock(key, in + i, block)) goto cleanup;

        // XOR with previous ciphertext (CBC step)
        for (size_t j = 0; j < AES_BLOCK_SIZE; j++)
            out[i + j] = block[j] ^ prev[j];
    
        // Update prev to current ciphertext
        SECURE_MEMCPY(prev, in + i, AES_BLOCK_SIZE);
    }

    ok = true;

cleanup:
    SECURE_ZERO(prev, sizeof(prev));
    SECURE_ZERO(block, sizeof(block));

    return ok;
}
