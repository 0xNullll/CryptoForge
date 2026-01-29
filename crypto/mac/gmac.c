/*
 * CryptoForge - gmac.c / GMAC (AES-GMAC) Implementation
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License in the file LICENSE in the
 * source distribution or at:
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * This software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
 * OR CONDITIONS OF ANY KIND, either express or implied. See the License
 * for the specific language governing permissions and limitations under
 * the License.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#include "../../include/crypto/gmac.h"

CF_STATUS ll_GMAC_Init(ll_GMAC_CTX *ctx, const ll_AES_KEY *key, const uint8_t *iv, size_t iv_len) {
    if (!ctx || !key || !iv)
        return CF_ERR_NULL_PTR;

    if (iv_len < AES_GCM_IV_MIN)
        return CF_ERR_MAC_BAD_IV_LEN;

    ll_GMAC_Reset(ctx);

    ctx->key = key;

    uint8_t zero[AES_BLOCK_SIZE] = {0};

    // H = AES_K(0)
    if (!ll_AES_EncryptBlock(key, zero, ctx->H))
        return CF_ERR_CIPHER_ENCRYPT;

    // J0 derivation
    if (iv_len == 12) {
        SECURE_MEMCPY(ctx->J0, iv, 12);
        ctx->J0[15] = 1;
    } else {
        uint8_t tmp[AES_BLOCK_SIZE] = {0};
        ll_GHASH_Process(ctx->H, iv, iv_len, tmp);

        uint8_t len_block[AES_BLOCK_SIZE] = {0};
        uint64_t iv_bits = iv_len * 8;
        for (int i = 0; i < 8; i++)
            len_block[8 + i] = (uint8_t)((iv_bits >> (56 - 8*i) & 0xFF));

        ll_GHASH_Process(ctx->H, len_block, AES_BLOCK_SIZE, tmp);
        SECURE_MEMCPY(ctx->J0, tmp, AES_BLOCK_SIZE);
        SECURE_ZERO(tmp, sizeof(tmp));
    }

    return CF_SUCCESS;
}

ll_GMAC_CTX* ll_GMAC_InitAlloc(const ll_AES_KEY *key, const uint8_t *iv, size_t iv_len, CF_STATUS *status) {
    if (!key || !iv) {
        if (status) *status = CF_ERR_INVALID_PARAM;
        return NULL;
    }

    ll_GMAC_CTX *ctx = (ll_GMAC_CTX *)SECURE_ALLOC(sizeof(ll_GMAC_CTX));
    if (!ctx) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    CF_STATUS st = ll_GMAC_Init(ctx, key, iv, iv_len);
    if (st != CF_SUCCESS) {
        SECURE_FREE(ctx, sizeof(ll_GMAC_CTX));
        if (status) *status = st;
        return NULL;
    }

    ctx->isHeapAlloc = 1;
    if (status) *status = CF_SUCCESS;
    return ctx;
}

CF_STATUS ll_GMAC_Update(ll_GMAC_CTX *ctx, const uint8_t *aad, size_t aad_len) {
    if (!ctx || !aad || aad_len == 0)
        return CF_ERR_INVALID_PARAM;

    if (ctx->isFinalized)
        return CF_ERR_CIPHER_FINALIZED;

    // Length limits (from NIST SP 800‑38D)
    if (aad_len > ((U64(0x1) << 61) - 1))
        return CF_ERR_INVALID_LEN;

    ll_GHASH_Process(ctx->H, aad, aad_len, ctx->X);
    ctx->aad_len += aad_len;

    return CF_SUCCESS;
}

CF_STATUS ll_GMAC_Final(ll_GMAC_CTX *ctx, uint8_t *tag, size_t tag_len) {
    if (!ctx || !tag || !IS_VALID_GCM_TAG_SIZE(tag_len))
        return CF_ERR_INVALID_PARAM;

    CF_STATUS ret = CF_SUCCESS;

    // Prepare length block: [aad_bits | 0] because GMAC has no plaintext
    uint8_t len_block[AES_BLOCK_SIZE] = {0};
    uint8_t tmp_X[AES_BLOCK_SIZE] = {0};
    uint8_t EK0[AES_BLOCK_SIZE] = {0};

    uint64_t aad_bits = ctx->aad_len * 8;

    // Big-endian encoding of AAD length
    for (int i = 0; i < 8; i++)
        len_block[i] = (uint8_t)((aad_bits >> (56 - 8*i)) & 0xFF);
    // Lower 64 bits remain zero for GMAC

    // XOR len_block into X
    SECURE_MEMCPY(tmp_X, ctx->X, AES_BLOCK_SIZE);
    for (int i = 0; i < AES_BLOCK_SIZE; i++)
        tmp_X[i] ^= len_block[i];

    // Multiply in GF(2^128)
    ll_gcm_mult(tmp_X, tmp_X, ctx->H);

    // Encrypt J0 to get EK0
    if (!ll_AES_EncryptBlock(ctx->key, ctx->J0, EK0)) {
        ret = CF_ERR_CIPHER_ENCRYPT;
        goto cleanup;
    }

    // Final GMAC tag = EK0 XOR GHASH output
    for (size_t i = 0; i < tag_len && i < AES_BLOCK_SIZE; i++)
        tag[i] = EK0[i] ^ tmp_X[i];

    ctx->isFinalized = 1;

cleanup:
    SECURE_ZERO(len_block, sizeof(len_block));
    SECURE_ZERO(tmp_X, sizeof(tmp_X));
    SECURE_ZERO(EK0, sizeof(EK0));
    return ret;
}

CF_STATUS ll_GMAC_Verify(
    const ll_AES_KEY *key,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *expected_tag, size_t tag_len) {
    if (!key || !iv || !aad || !expected_tag)
        return CF_ERR_NULL_PTR;

    if (iv_len < AES_GCM_IV_MIN || !IS_VALID_GCM_TAG_SIZE(tag_len))
        return CF_ERR_INVALID_PARAM;

    uint8_t tag[AES_BLOCK_SIZE];
    SECURE_ZERO(tag, sizeof(tag));

    CF_STATUS st = CF_SUCCESS;
    ll_GMAC_CTX ctx;
    SECURE_ZERO(&ctx, sizeof(ctx));

    // Initialize context
    st = ll_GMAC_Init(&ctx, key, iv, iv_len);
    if (st != CF_SUCCESS) goto cleanup;

    // Process AAD
    if (aad_len > 0) {
        st = ll_GMAC_Update(&ctx, aad, aad_len);
        if (st != CF_SUCCESS) goto cleanup;
    }

    // Finalize
    st = ll_GMAC_Final(&ctx, tag, tag_len);
    if (st != CF_SUCCESS) goto cleanup;

    // Constant-time compare
    st = SECURE_MEM_EQUAL(tag, expected_tag, tag_len) ? CF_SUCCESS : CF_ERR_MAC_VERIFY;

cleanup:
    SECURE_ZERO(&ctx, sizeof(ctx));
    SECURE_ZERO(tag, sizeof(tag));
    return st;
}


CF_STATUS ll_GMAC_Reset(ll_GMAC_CTX *ctx) {
    if (!ctx || !ctx->key)
        return CF_ERR_NULL_PTR;

    int wasHeapAlloc = ctx->isHeapAlloc;

    // Zero all sensitive internal data
    SECURE_ZERO(ctx->H, sizeof(ctx->H));
    SECURE_ZERO(ctx->J0, sizeof(ctx->J0));
    SECURE_ZERO(ctx->X, sizeof(ctx->X));

    // Reset lengths and state
    ctx->aad_len = 0;
    ctx->isFinalized = 0;
    
    // Key pointer is not freed, assumed managed externally
    ctx->key = NULL;

    ctx->isHeapAlloc = wasHeapAlloc;

    return CF_SUCCESS;
}

CF_STATUS ll_GMAC_Free(ll_GMAC_CTX **p_ctx) {
    if (!p_ctx || !*p_ctx)
        return CF_ERR_NULL_PTR;

    ll_GMAC_CTX *ctx = *p_ctx;
    int wasHeapAlloc = ctx->isHeapAlloc;

    ll_GMAC_Reset(ctx);

    // Free the outer struct if heap-allocated
    if (wasHeapAlloc) {
        SECURE_ZERO(ctx, sizeof(ll_GMAC_CTX));
        SECURE_FREE(ctx, sizeof(ll_GMAC_CTX));
        *p_ctx = NULL;
    }

    return CF_SUCCESS;
}
