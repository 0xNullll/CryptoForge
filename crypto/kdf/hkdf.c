/*
 * CryptoForge - hkdf.c / HKDF (HKDF-HMAC-SHA1, SHA2, SHA3) Implementation
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

#include "../../include/crypto/hkdf.h"

CF_STATUS ll_HKDF_Init(ll_HKDF_CTX *ctx, const CF_MD *md, const uint8_t *info, size_t info_len) {
    if (!ctx || !md)
        return CF_ERR_NULL_PTR; 

    // HKDF is not compatible with XOF hash functions, as per HMAC-based design rules
    if (CF_IS_XOF(md->id))
        return CF_ERR_UNSUPPORTED;

    // nothing to write
    if (info && info_len == 0)
        return CF_ERR_INVALID_PARAM;

    ll_HKDF_Reset(ctx);
        
    ctx->md = md;

    if (info) {
        ctx->info = (uint8_t *)SECURE_ALLOC(info_len);
        SECURE_MEMCPY((void *)ctx->info, info, info_len);

        if (!ctx->info)
            return CF_ERR_ALLOC_FAILED;

        ctx->info_len = info_len;
    }

    return CF_SUCCESS;
}

ll_HKDF_CTX* ll_HKDF_InitAlloc(const CF_MD *md, const uint8_t *info, size_t info_len, CF_STATUS *status) {
    if (!md) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    ll_HKDF_CTX *ctx = (ll_HKDF_CTX*)SECURE_ALLOC(sizeof(ll_HKDF_CTX));
    if (!ctx) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    CF_STATUS st = ll_HKDF_Init(ctx, md, info, info_len);
    if (st != CF_SUCCESS) {
        SECURE_FREE(ctx, sizeof(ll_HKDF_CTX));
        if (status) *status = st;
        return NULL;
    }

    ctx->isHeapAlloc = 1;
    if (status) *status = CF_SUCCESS;
    return ctx;
}

CF_STATUS ll_HKDF_Extract(
    ll_HKDF_CTX *ctx,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *ikm, size_t ikm_len) {
    if (!ctx || !ctx->md)
        return CF_ERR_NULL_PTR;

    size_t hash_len = ctx->md->digest_size;  // always PRK = hash output size

    CF_STATUS st;
    ll_HMAC_CTX hmac_ctx = {0};

    // HMAC key = salt
    if (salt && salt_len > 0)
        st = ll_HMAC_Init(&hmac_ctx, ctx->md, salt, salt_len);
    else
        st = ll_HMAC_Init(&hmac_ctx, ctx->md, (const uint8_t *)"", 0);

    if (st != CF_SUCCESS) {
        return st;
    }

    // Feed the input key material (IKM) into HMAC
    if (salt && salt_len > 0)
        st = ll_HMAC_Update(&hmac_ctx, ikm, ikm_len);
    else
        st = ll_HMAC_Update(&hmac_ctx, (const uint8_t *)"", 0);

    if (st != CF_SUCCESS) {
        ll_HMAC_Reset(&hmac_ctx);
        return st;
    }

    // Allocate and compute PRK
    ctx->prk = (uint8_t *)SECURE_ALLOC(hash_len);
    if (!ctx->prk) {
        ll_HMAC_Reset(&hmac_ctx);
        return CF_ERR_ALLOC_FAILED;
    }

    st = ll_HMAC_Final(&hmac_ctx, ctx->prk, hash_len);
    ll_HMAC_Reset(&hmac_ctx);
    if (st != CF_SUCCESS) {
        SECURE_FREE((void *)ctx->prk, hash_len);
        return st;
    }

    ctx->prk_len = hash_len;
    return CF_SUCCESS;
}

CF_STATUS ll_HKDF_Expand(
    ll_HKDF_CTX *ctx,
    uint8_t *okm, size_t okm_len,
    const uint8_t *new_info, size_t new_info_len) {
    if (!ctx || !ctx->md || !ctx->prk || !okm)
        return CF_ERR_NULL_PTR;

    if (okm_len == 0)
        return CF_ERR_INVALID_LEN;

    if (new_info && new_info_len == 0)
        return CF_ERR_INVALID_PARAM;

    const size_t hash_len = ctx->md->digest_size;
    const size_t max_okm = LL_HKDF_MAX_OKM(hash_len); // RFC 5869 max 255 blocks

    if (okm_len > max_okm)
        return CF_ERR_LIMIT_EXCEEDED;

    // Only replace info once, before generating blocks
    if (new_info) {
        if (ctx->info) {
            SECURE_FREE(ctx->info, ctx->info_len);
            ctx->info = NULL;
            ctx->info_len = 0;
        }

        ctx->info = (uint8_t *)SECURE_ALLOC(new_info_len);
        if (!ctx->info)
            return CF_ERR_ALLOC_FAILED;

        SECURE_MEMCPY(ctx->info, new_info, new_info_len);
        ctx->info_len = new_info_len;
    }

    // Prepare for multi-block generation
    SECURE_ZERO(ctx->prev_block, sizeof(ctx->prev_block));
    size_t prev_block_len = 0;
    ctx->counter = 0;

    ll_HMAC_CTX *hmac_ctx = (ll_HMAC_CTX *)SECURE_ALLOC(sizeof(ll_HMAC_CTX));
    if (!hmac_ctx)
        return CF_ERR_ALLOC_FAILED;

    CF_STATUS st;
    size_t generated = 0;
    uint8_t block[CF_MAX_DEFAULT_BLOCK_SIZE];

    while (generated < okm_len) {
        if (ctx->counter >= LL_HKDF_MAX_BLOCKS) { // RFC 5869 max 255 blocks
            st = CF_ERR_LIMIT_EXCEEDED;
            goto cleanup;
        }

        ctx->counter++; // Block index (1..255)

        st = ll_HMAC_Init(hmac_ctx, ctx->md, ctx->prk, ctx->prk_len);
        if (st != CF_SUCCESS)
            goto cleanup;

        // Feed previous block if exists
        if (prev_block_len)
            st = ll_HMAC_Update(hmac_ctx, ctx->prev_block, prev_block_len);
        if (st != CF_SUCCESS)
            goto cleanup;

        // Feed info
        if (ctx->info && ctx->info_len)
            st = ll_HMAC_Update(hmac_ctx, ctx->info, ctx->info_len);
        if (st != CF_SUCCESS)
            goto cleanup;

        // Feed counter
        st = ll_HMAC_Update(hmac_ctx, &ctx->counter, 1);
        if (st != CF_SUCCESS)
            goto cleanup;

        // Finalize block
        st = ll_HMAC_Final(hmac_ctx, block, hash_len);
        if (st != CF_SUCCESS)
            goto cleanup;

        // clean internal buffers
        ll_HMAC_Reset(hmac_ctx);

        // Copy required bytes to output
        size_t to_copy = (okm_len - generated > hash_len) ? hash_len : (okm_len - generated);
        SECURE_MEMCPY(okm + generated, block, to_copy);
        generated += to_copy;

        // Save current block for next iteration
        SECURE_MEMCPY(ctx->prev_block, block, hash_len);
        prev_block_len = hash_len;
    }

    SECURE_ZERO(block, sizeof(block));
    st = CF_SUCCESS;

cleanup:
    ll_HMAC_Reset(hmac_ctx);
    SECURE_FREE(hmac_ctx, sizeof(hmac_ctx));
    SECURE_ZERO(block, sizeof(block));
    return st;
}

CF_STATUS ll_HKDF_Reset(ll_HKDF_CTX *ctx) {
    if (!ctx)
        return CF_ERR_NULL_PTR;

    if (ctx->prk) {
        if (ctx->prk_len == 0)
            return CF_ERR_CTX_CORRUPT;
        SECURE_FREE(ctx->prk, ctx->prk_len);
    }

    if (ctx->info) {
        if (ctx->info_len == 0)
            return CF_ERR_CTX_CORRUPT;
        SECURE_FREE(ctx->info, ctx->info_len);
    }

    SECURE_ZERO(ctx->prev_block, sizeof(ctx->prev_block));

    ctx->md = NULL;
    ctx->prk_len = 0;
    ctx->counter = 0;
    ctx->info_len = 0;

    return CF_SUCCESS;
}

CF_STATUS ll_HKDF_Free(ll_HKDF_CTX **p_ctx) {
    if (!p_ctx || !*p_ctx)
        return CF_ERR_NULL_PTR;

    ll_HKDF_CTX *ctx = *p_ctx;

    CF_STATUS st = ll_HKDF_Reset(ctx);
    if (st != CF_SUCCESS)
        return st;

    if (ctx->isHeapAlloc)
        SECURE_FREE(ctx, sizeof(*ctx));   // free only if heap-allocated

    ctx = NULL;  // nullify caller pointer

    return CF_SUCCESS;
}

CF_STATUS ll_HKDF_CloneCtx(ll_HKDF_CTX *ctx_dest, const ll_HKDF_CTX *ctx_src) {
    if (!ctx_dest || !ctx_src) return CF_ERR_NULL_PTR;

    // Copy top-level context first (fixed-size parts only)
    ll_HKDF_CTX tmp = *ctx_src; // shallow copy

    ll_HKDF_Reset(ctx_dest);

    SECURE_MEMCPY(ctx_dest, &tmp, sizeof(*ctx_dest));

    ctx_dest->isHeapAlloc = 0; // cloned context will not own heap allocations by default

    // Clone PRK if exists
    if (ctx_src->prk && ctx_src->prk_len > 0) {
        ctx_dest->prk = (uint8_t *)SECURE_ALLOC(ctx_src->prk_len);
        if (!ctx_dest->prk) return CF_ERR_ALLOC_FAILED;
        SECURE_MEMCPY(ctx_dest->prk, ctx_src->prk, ctx_src->prk_len);
        ctx_dest->prk_len = ctx_src->prk_len;
    }

    // Clone info if exists
    if (ctx_src->info && ctx_src->info_len > 0) {
        ctx_dest->info = (uint8_t *)SECURE_ALLOC(ctx_src->info_len);
        if (!ctx_dest->info) {
            SECURE_FREE(ctx_dest->prk, ctx_dest->prk_len);
            ctx_dest->prk = NULL;
            return CF_ERR_ALLOC_FAILED;
        }
        SECURE_MEMCPY(ctx_dest->info, ctx_src->info, ctx_src->info_len);
        ctx_dest->info_len = ctx_src->info_len;
    }

    return CF_SUCCESS;
}

ll_HKDF_CTX *ll_HKDF_CloneCtxAlloc(const ll_HKDF_CTX *ctx_src, CF_STATUS *status) {
    if (!ctx_src) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    // Allocate top-level context
    ll_HKDF_CTX *dst = (ll_HKDF_CTX *)SECURE_ALLOC(sizeof(ll_HKDF_CTX));
    if (!dst) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Initialize clone
    CF_STATUS st = ll_HKDF_CloneCtx(dst, ctx_src);
    if (status) *status = st;
    
    if (st != CF_SUCCESS) {
        SECURE_FREE(dst, sizeof(*dst));
        return NULL;
    }

    dst->isHeapAlloc = 1; // library owns this memory
    return dst;
}