/*
 * CryptoForge - cmac.c / CMAC (AES-CMAC) Implementation
 * Copyright (C) 2025 0xNullll
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the MIT License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * You should have received a copy of the MIT License along with this program.
 * If not, see <https://opensource.org/licenses/MIT>.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#include "cmac.h"

/*
 * Multiplication by u in the Galois field for AES (GF(2^128))
 *
 * As defined in NIST SP 800-38B, this can be computed:
 *
 *   If MSB(input) = 0, then output = input << 1
 *   If MSB(input) = 1, then output = (input << 1) ^ R_128
 *   with R_128 = 0x87
 *
 * Input and output MUST NOT point to the same buffer.
 * Block size must be 16 bytes (AES block size).
 */
static void ll_AES_CMAC_MultiplyByU(const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]) {
    const uint8_t R_128 = 0x87;
    uint32_t overflow = 0;

    // Process 4-byte chunks
    for (int i = AES_BLOCK_SIZE - 4; i >= 0; i -= 4) {
        uint32_t in32 = AES_LOAD32(&in[i]);
        uint32_t new_overflow = in32 >> 31;
        in32 = (in32 << 1) | overflow;
        AES_STORE32(&out[i], in32);
        overflow = new_overflow;
    }

    if (in[0] & 0x80)
        out[AES_BLOCK_SIZE - 1] ^= R_128;
}

/*
 * Generate subkeys K1 and K2
 *
 * - As specified in RFC 4493, section 2.3 (Subkey Generation Algorithm)
 */
static bool ll_CMAC_GenerateSubKeys(const ll_AES_KEY *aes_key,
                                    uint8_t K1[AES_BLOCK_SIZE],
                                    uint8_t K2[AES_BLOCK_SIZE]) {
    uint8_t zero_block[AES_BLOCK_SIZE] = {0}; // AES zero block
    uint8_t L[AES_BLOCK_SIZE] = {0};          // Temporary encrypted value

    // Encrypt zero block to produce L
    if (!ll_AES_EncryptBlock(aes_key, zero_block, L))
        goto cleanup;

    //
    // Generate subkeys K1 and K2
    //
    ll_AES_CMAC_MultiplyByU(K1, L);
    ll_AES_CMAC_MultiplyByU(K2, K1);

    SECURE_ZERO(L, sizeof(L));
    return true;

cleanup:
    SECURE_ZERO(L, sizeof(L));
    return false;
}

static void ll_CMAC_Pad(uint8_t padded_block[AES_BLOCK_SIZE], size_t padded_block_len,
                     const uint8_t last_block[AES_BLOCK_SIZE], size_t last_block_len) {

    for (size_t j = 0; j < padded_block_len; j++) {
        if (j < last_block_len) {
            padded_block[j] = last_block[j];
        } else if (j == last_block_len) {
            padded_block[j] = 0x80;
        } else {
            padded_block[j] = 0x00;
        }
    }
}

CF_STATUS ll_CMAC_Init(ll_CMAC_CTX *ctx, const ll_AES_KEY *key) {
    if (!ctx || !key) return CF_ERR_NULL_PTR;

    ctx->key = key;

    if (!ll_CMAC_GenerateSubKeys(ctx->key, ctx->K1, ctx->K2)) return CF_ERR_CIPHER_KEY_SETUP;

    ctx->isFinalized = 0;
    ctx->isHeapAlloc = 0;

    return CF_SUCCESS;
}

CF_STATUS ll_CMAC_Update(ll_CMAC_CTX *ctx, const uint8_t *data, size_t data_len) {
    if (!ctx || !ctx->key || !data)
        return CF_ERR_NULL_PTR;

    if (data && data_len == 0)
        return CF_ERR_INVALID_LEN; 

    while (data_len > 0) {
        size_t to_copy = AES_BLOCK_SIZE - ctx->buffer_len;
        if (to_copy > data_len) to_copy = data_len;

        SECURE_MEMCPY(&ctx->buffer[ctx->buffer_len], data, to_copy);
        ctx->buffer_len += to_copy;
        data += to_copy;
        data_len -= to_copy;

        if (ctx->buffer_len == AES_BLOCK_SIZE) {
            // XOR with last_block
            for (int i = 0; i < AES_BLOCK_SIZE; i++)
                ctx->buffer[i] ^= ctx->last_block[i];

            // Encrypt and store in last_block
            if (!ll_AES_EncryptBlock(ctx->key, ctx->buffer, ctx->last_block)) return CF_ERR_CIPHER_ENCRYPT;

            ctx->buffer_len = 0;
        }
    }

    return CF_SUCCESS;
}

CF_STATUS ll_CMAC_Final(ll_CMAC_CTX *ctx, uint8_t *tag, size_t tag_len) {

}