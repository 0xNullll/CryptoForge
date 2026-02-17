/*
 * CryptoForge - cmac.c / CMAC (AES-CMAC) Implementation
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against WyChaProof test vectors. No hardware optimizations. Use with caution.
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
        uint32_t in32 = LOAD32BE(&in[i]);
        uint32_t new_overflow = in32 >> 31;
        in32 = (in32 << 1) | overflow;
        STORE32BE(&out[i], in32);
        overflow = new_overflow;
    }

    if (in[0] & 0x80)
        out[AES_BLOCK_SIZE - 1] ^= R_128;
}

/*
 * Generate subkeys K1 and K2
 *
 * As specified in RFC 4493, section 2.3 (Subkey Generation Algorithm):
 *
 *   1. Encrypt the zero block with the AES key to produce L
 *   2. Compute K1 = L * u in GF(2^128)
 *   3. Compute K2 = K1 * u in GF(2^128)
 *
 * These subkeys are used in CMAC for padding the last block.
 * Temporary values are securely zeroed before returning.
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

    // K1 = L * u in GF(2^128)
    ll_AES_CMAC_MultiplyByU(L, K1);

    // K2 = K1 * u in GF(2^128)
    ll_AES_CMAC_MultiplyByU(K1, K2);

    SECURE_ZERO(L, sizeof(L));
    return true;

cleanup:
    SECURE_ZERO(L, sizeof(L));
    return false;
}

/*
 * CMAC pad the last block
 *
 * As specified in RFC 4493, section 2.4 (MAC Generation Algorithm):
 *
 *   - Copy existing bytes from the last block
 *   - Append 0x80 immediately after the data
 *   - Fill remaining bytes with 0x00
 *
 * Ensures the last block is always 16 bytes (AES block size).
 * Input and output buffers MUST NOT overlap.
 */
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

    if (ctx->isHeapAlloc != 0 && ctx->isHeapAlloc != 1)
        return CF_ERR_CTX_UNINITIALIZED;

    ll_CMAC_Reset(ctx);

    ctx->key = key;

    return CF_SUCCESS;
}

ll_CMAC_CTX* ll_CMAC_InitAlloc(const ll_AES_KEY *key, CF_STATUS *status) {
    if (!key) {
        if (status) *status = CF_ERR_INVALID_PARAM;
        return NULL;
    }

    ll_CMAC_CTX *ctx = (ll_CMAC_CTX *)SECURE_ALLOC(sizeof(ll_CMAC_CTX));
    if (!ctx) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    CF_STATUS st = ll_CMAC_Init(ctx, key);
    if (st != CF_SUCCESS) {
        SECURE_FREE(ctx, sizeof(ll_CMAC_CTX));
        if (status) *status = st;
        return NULL;
    }

    ctx->isHeapAlloc = 1;
    if (status) *status = CF_SUCCESS;
    return ctx;
}

CF_STATUS ll_CMAC_Update(ll_CMAC_CTX *ctx, const uint8_t *data, size_t data_len) {
        if (!ctx || !ctx->key || !data)
        return CF_ERR_NULL_PTR;

    if (ctx->isFinalized)
        return CF_ERR_MAC_FINALIZED;

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
        return CF_ERR_MAC_INVALID_TAG_LEN;

    if (ctx->isFinalized)
        return CF_ERR_CIPHER_FINALIZED;

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

    // Free the outer struct if heap-allocated
    if (wasHeapAlloc)
        SECURE_FREE(ctx, sizeof(ll_CMAC_CTX));

    return CF_SUCCESS;
}

CF_STATUS ll_CMAC_Verify(
    const ll_AES_KEY *key,
    const uint8_t *data, size_t data_len,
    const uint8_t *expected_tag, size_t tag_len) {
    if (!key || !expected_tag)
        return CF_ERR_NULL_PTR;

    if (tag_len < 4 || tag_len > AES_BLOCK_SIZE)
        return CF_ERR_MAC_INVALID_TAG_LEN;

    CF_STATUS st = CF_SUCCESS;

    uint8_t tag[AES_BLOCK_SIZE] = {0};
    ll_CMAC_CTX ctx = {0};

    // Initialize context with key
    st = ll_CMAC_Init(&ctx, key);
    if (st != CF_SUCCESS) goto cleanup;

    // Update with message data
    st = ll_CMAC_Update(&ctx, data, data_len);
    if (st != CF_SUCCESS) goto cleanup;

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

CF_STATUS ll_CMAC_CloneCtx(ll_CMAC_CTX *ctx_dest, const ll_CMAC_CTX *ctx_src) {
    if (!ctx_dest || !ctx_src)
        return CF_ERR_NULL_PTR;

    // Zero the destination first
    ll_CMAC_Reset(ctx_dest);

    ctx_dest->key = ctx_src->key;

    ctx_dest->unprocessed_len = ctx_src->unprocessed_len;
    SECURE_MEMCPY(ctx_dest->unprocessed_block,
                ctx_src->unprocessed_block,
                sizeof(ctx_dest->unprocessed_block));

    SECURE_MEMCPY(ctx_dest->last_block,
                ctx_src->last_block,
                sizeof(ctx_dest->last_block));

    ctx_dest->isFinalized = ctx_src->isFinalized;
    ctx_dest->isHeapAlloc = 0; // dst is “new”, caller owns it

    return CF_SUCCESS;
}

ll_CMAC_CTX* ll_CMAC_CloneCtxAlloc(const ll_CMAC_CTX *ctx_src, CF_STATUS *status) {
    if (!ctx_src) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    // Allocate the destination context
    ll_CMAC_CTX *ctx_dest = (ll_CMAC_CTX *)SECURE_ALLOC(sizeof(ll_CMAC_CTX));
    if (!ctx_dest) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Use the in-place clone function
    CF_STATUS ret = ll_CMAC_CloneCtx(ctx_dest, ctx_src);
    if (ret != CF_SUCCESS) {
        SECURE_FREE(ctx_dest, sizeof(ll_CMAC_CTX));
        return NULL;
    }

    ctx_dest->isHeapAlloc = 1; // library owns this memory

    return ctx_dest;
}
