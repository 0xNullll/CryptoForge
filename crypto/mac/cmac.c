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

#include "../../include/crypto/cmac.h"

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
    ll_AES_CMAC_MultiplyByU(L, K1);
    ll_AES_CMAC_MultiplyByU(K1, K2);

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

    ll_CMAC_Reset(ctx);

    ctx->key = key;

    return CF_SUCCESS;
}

CF_STATUS ll_CMAC_Update(ll_CMAC_CTX *ctx, const uint8_t *data, size_t data_len) {
        if (!ctx || !ctx->key || !data)
        return CF_ERR_NULL_PTR;

    size_t offset = 0;

    // If we have leftover bytes from previous update, fill unprocessed_block
    if (ctx->unprocessed_len > 0) {
        size_t to_copy = AES_BLOCK_SIZE - ctx->unprocessed_len;
        if (to_copy > data_len) to_copy = data_len;

        SECURE_MEMCPY(ctx->unprocessed_block + ctx->unprocessed_len, data + offset, to_copy);
        ctx->unprocessed_len += to_copy;
        offset += to_copy;
        data_len -= to_copy;

        if (ctx->unprocessed_len == AES_BLOCK_SIZE) {
            // XOR with last_block
            for (int i = 0; i < AES_BLOCK_SIZE; i++)
                ctx->unprocessed_block[i] ^= ctx->last_block[i];

            // Encrypt
            if (!ll_AES_EncryptBlock(ctx->key, ctx->unprocessed_block, ctx->last_block))
                return CF_ERR_CIPHER_ENCRYPT;

            ctx->unprocessed_len = 0;
        }
    }

    // Process all full blocks except the last one
    while (data_len > AES_BLOCK_SIZE) {
        uint8_t block[AES_BLOCK_SIZE];
        SECURE_MEMCPY(block, data + offset, AES_BLOCK_SIZE);

        for (int i = 0; i < AES_BLOCK_SIZE; i++)
            block[i] ^= ctx->last_block[i];

        if (!ll_AES_EncryptBlock(ctx->key, block, ctx->last_block)) {
            return CF_ERR_CIPHER_ENCRYPT;
        }

        offset += AES_BLOCK_SIZE;
        data_len -= AES_BLOCK_SIZE;
    }

    // Store remaining bytes in unprocessed_block
    if (data_len > 0) {
        SECURE_MEMCPY(ctx->unprocessed_block, data + offset, data_len);
        ctx->unprocessed_len = data_len;
    }

    return CF_SUCCESS;
}

CF_STATUS ll_CMAC_Final(ll_CMAC_CTX *ctx, uint8_t *tag, size_t tag_len) {
    if (!ctx || !ctx->key || !tag)
        return CF_ERR_NULL_PTR;

    if (tag_len < 4 || tag_len > AES_BLOCK_SIZE)
        return CF_ERR_MAC_BAD_TAG_LEN;

    uint8_t K1[AES_BLOCK_SIZE] = {0};
    uint8_t K2[AES_BLOCK_SIZE] = {0};
    uint8_t M_last[AES_BLOCK_SIZE] = {0};
    CF_STATUS ret = CF_SUCCESS;

    if (!ll_CMAC_GenerateSubKeys(ctx->key, K1, K2)) {
        ret = CF_ERR_CIPHER_KEY_SETUP;
        goto cleanup;
    }

    // Always treat unprocessed_block as last block
    if (ctx->unprocessed_len == AES_BLOCK_SIZE) {
        // Full last block → XOR with K1
        for (int i = 0; i < AES_BLOCK_SIZE; i++)
            M_last[i] = ctx->unprocessed_block[i] ^ K1[i];
    } else {
        // Partial last block -> pad and XOR with K2
        ll_CMAC_Pad(M_last, AES_BLOCK_SIZE, ctx->unprocessed_block, ctx->unprocessed_len);
        for (int i = 0; i < AES_BLOCK_SIZE; i++)
            M_last[i] ^= K2[i];
    }

    // XOR with running state (last_block)
    for (int i = 0; i < AES_BLOCK_SIZE; i++)
        M_last[i] ^= ctx->last_block[i];

    // Encrypt final block → tag
    if (!ll_AES_EncryptBlock(ctx->key, M_last, M_last)) {
        ret = CF_ERR_CIPHER_ENCRYPT;
        goto cleanup;
    }

    SECURE_MEMCPY(tag, M_last, tag_len);

    ctx->isFinalized = 1;
    ctx->unprocessed_len = 0;
    SECURE_ZERO(ctx->unprocessed_block, sizeof(ctx->unprocessed_block));

cleanup:
    SECURE_ZERO(K1, sizeof(K1));
    SECURE_ZERO(K2, sizeof(K2));
    SECURE_ZERO(M_last, sizeof(M_last));

    return ret;
}

CF_STATUS ll_CMAC_Verify(
    const ll_AES_KEY *key,
    const uint8_t *data, size_t data_len,
    const uint8_t *expected_tag, size_t tag_len) {
    if (!key || !expected_tag)
        return CF_ERR_NULL_PTR;

    if (tag_len < 4 || tag_len > AES_BLOCK_SIZE)
        return CF_ERR_MAC_BAD_TAG_LEN;

    CF_STATUS st = CF_SUCCESS;
    uint8_t tag[AES_BLOCK_SIZE];
    SECURE_ZERO(tag, sizeof(tag));

    ll_CMAC_CTX ctx;
    SECURE_ZERO(&ctx, sizeof(ctx));

    // Initialize context with key
    st = ll_CMAC_Init(&ctx, key);
    if (st != CF_SUCCESS) goto cleanup;

    // Update with message data
    if (data_len > 0) {
        st = ll_CMAC_Update(&ctx, data, data_len);
        if (st != CF_SUCCESS) goto cleanup;
    }

    // Finalize and compute tag
    st = ll_CMAC_Final(&ctx, tag, tag_len);
    if (st != CF_SUCCESS) goto cleanup;

    // Constant-time comparison
    st = SECURE_MEM_EQUAL(tag, expected_tag, tag_len) ? CF_SUCCESS : CF_ERR_MAC_VERIFY;

cleanup:
    ll_CMAC_Reset(&ctx);
    SECURE_ZERO(tag, sizeof(tag));

    return st;
}

CF_STATUS ll_CMAC_Reset(ll_CMAC_CTX *ctx) {
    if (!ctx || !ctx->key)
        return CF_ERR_NULL_PTR;

    int wasHeapAlloc = ctx->isHeapAlloc;

    // Zero all sensitive internal data
    SECURE_ZERO(ctx->unprocessed_block, sizeof(ctx->unprocessed_block));
    SECURE_ZERO(ctx->last_block, sizeof(ctx->last_block));

    // Reset lengths and state
    ctx->isFinalized = 0;
    ctx->unprocessed_len = 0;

    // Key pointer is not freed, assumed managed externally
    ctx->key = NULL;

    ctx->isHeapAlloc = wasHeapAlloc;

    return CF_SUCCESS;
}

CF_STATUS ll_CMAC_Free(ll_CMAC_CTX **p_ctx) {
    if (!p_ctx || !*p_ctx)
        return CF_ERR_NULL_PTR;

    ll_CMAC_CTX *ctx = *p_ctx;
    int wasHeapAlloc = ctx->isHeapAlloc;

    ll_CMAC_Reset(ctx);

    if (wasHeapAlloc) {
        SECURE_ZERO(ctx, sizeof(ll_CMAC_CTX));
        SECURE_FREE(ctx, sizeof(ll_CMAC_CTX));
        *p_ctx = NULL;
    }

    return CF_SUCCESS;
}