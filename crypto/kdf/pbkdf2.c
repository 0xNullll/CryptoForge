/*
 * CryptoForge - pbkdf2.c / PBKDF2 (PBKDF2-HMAC-SHA1, SHA2, SHA3) Implementation
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

#include "../../include/crypto/pbkdf2.h"

CF_STATUS ll_PBKDF2_Init(
    ll_PBKDF2_CTX *ctx,
    const CF_MD *md,
    const uint8_t *password, size_t password_len) {
    if (!ctx || !md)
        return CF_ERR_NULL_PTR; 

    // PBKDF2 is not compatible with XOF hash functions, as per HMAC-based design rules
    if (CF_IS_XOF(md->id))
        return CF_ERR_UNSUPPORTED;

    // nothing to write
    if (password && password_len == 0)
        return CF_ERR_INVALID_PARAM;

    ll_PBKDF2_Reset(ctx);
        
    ctx->md = md;

    if (password) {
        ctx->password = (uint8_t *)SECURE_ALLOC(password_len);
        SECURE_MEMCPY((void *)ctx->password, password, password_len);

        if (!ctx->password)
            return CF_ERR_ALLOC_FAILED;

        ctx->password_len = password_len;
    }

    return CF_SUCCESS;
}

ll_PBKDF2_CTX* ll_PBKDF2_InitAlloc(
    const CF_MD *md,
    const uint8_t *password, size_t password_len,
    CF_STATUS *status) {
    if (!md) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    ll_PBKDF2_CTX *ctx = (ll_PBKDF2_CTX*)SECURE_ALLOC(sizeof(ll_PBKDF2_CTX));
    if (!ctx) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    CF_STATUS st = ll_PBKDF2_Init(ctx, md, password, password_len);
    if (st != CF_SUCCESS) {
        SECURE_FREE(ctx, sizeof(ll_PBKDF2_CTX));
        if (status) *status = st;
        return NULL;
    }

    ctx->isHeapAlloc = 1;
    if (status) *status = CF_SUCCESS;
    return ctx;
}

CF_STATUS ll_PBKDF2_Extract(
    ll_PBKDF2_CTX *ctx,
    const uint8_t *salt, size_t salt_len) {
    if (!ctx || !ctx->md || !ctx->password)
        return CF_ERR_NULL_PTR;

    size_t hash_len = ctx->md->digest_size;  // PRK length = hash output size
    CF_STATUS st;

    // Allocate PRK buffer if not already
    if (!ctx->prk) {
        ctx->prk = (uint8_t *)SECURE_ALLOC(hash_len);
        if (!ctx->prk)
            return CF_ERR_ALLOC_FAILED;
    }

    ll_HMAC_CTX hmac_ctx = {0};

    // HMAC key = password
    st = ll_HMAC_Init(&hmac_ctx, ctx->md, ctx->password, ctx->password_len);
    if (st != CF_SUCCESS)
        return st;

    // Feed salt (or empty string if salt is NULL)
    if (salt && salt_len > 0)
        st = ll_HMAC_Update(&hmac_ctx, salt, salt_len);
    else
        st = ll_HMAC_Update(&hmac_ctx, (const uint8_t *)"", 0);

    if (st != CF_SUCCESS) {
        ll_HMAC_Reset(&hmac_ctx);
        return st;
    }

    // Compute PRK and store in context
    st = ll_HMAC_Final(&hmac_ctx, ctx->prk, hash_len);
    ll_HMAC_Reset(&hmac_ctx);
    if (st != CF_SUCCESS) {
        SECURE_FREE(ctx->prk, hash_len);
        return st;
    }

    ctx->prk_len = hash_len;

    // Prepare for Expand: first block index = 1
    ctx->block_index = 1;
    ctx->generated_len = 0;

    return CF_SUCCESS;
}

CF_STATUS ll_PBKDF2_Reset(ll_PBKDF2_CTX *ctx) {
    if (!ctx)
        return CF_ERR_NULL_PTR;

    if (ctx->password) {
        if (ctx->password_len == 0)
            return CF_ERR_CTX_CORRUPT;
        SECURE_FREE(ctx->password, ctx->password_len);
    }

    if (ctx->prk) {
        if (ctx->prk_len == 0)
            return CF_ERR_CTX_CORRUPT;
        SECURE_FREE(ctx->prk, ctx->prk_len);
    }

    SECURE_ZERO(ctx->prev_block, sizeof(ctx->prev_block));

    ctx->md = NULL;
    ctx->password_len = 0;
    ctx->iterations = 0;
    ctx->dk_len = 0;
    ctx->block_index = 0;
    ctx->generated_len = 0;

    return CF_SUCCESS;
}

CF_STATUS ll_PBKDF2_Free(ll_PBKDF2_CTX **p_ctx) {
    if (!p_ctx || !*p_ctx)
        return CF_ERR_NULL_PTR;

    ll_PBKDF2_CTX *ctx = *p_ctx;

    CF_STATUS st = ll_PBKDF2_Reset(ctx);
    if (st != CF_SUCCESS)
        return st;

    if (ctx->isHeapAlloc)
        SECURE_FREE(ctx, sizeof(*ctx));   // free only if heap-allocated

    ctx = NULL;  // nullify caller pointer

    return CF_SUCCESS;
}

uint32_t ll_PBKDF2_RecommendedIterations(const ll_PBKDF2_CTX *ctx) {
    if (!ctx->md) return 0;

    // Convert digest size to bits
    double hash_bits = (double)(ctx->md->digest_size * 8);

    // Formula: iterations ≈ 2.4e9 * hash_bits^(-1.64)
    double iter = 2.4e9 * pow(hash_bits, -1.64);

    // Clamp to at least 1 iteration
    if (iter < 1.0) iter = 1.0;

    return (uint32_t)(iter + 0.5); // round to nearest integer
}
