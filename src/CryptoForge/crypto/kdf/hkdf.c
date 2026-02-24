/*
 * CryptoForge - hkdf.c / HKDF (HKDF-HMAC-SHA1, SHA2, SHA3) Implementation
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "../../include/crypto/hkdf.h"

CF_STATUS ll_HKDF_Init(ll_HKDF_CTX *ctx, const CF_HASH *hash, const uint8_t *info, size_t info_len) {
    if (!ctx || !hash)
        return CF_ERR_NULL_PTR; 

    // HKDF is not compatible with XOF hash functions, as per HMAC-based design rules
    if (CF_IS_XOF(hash->id))
        return CF_ERR_UNSUPPORTED;

    ll_HKDF_Reset(ctx);
        
    ctx->hash = hash;
    
    ctx->info = info;
    ctx->info_len = info_len;

    return CF_SUCCESS;
}

ll_HKDF_CTX* ll_HKDF_InitAlloc(const CF_HASH *hash, const uint8_t *info, size_t info_len, CF_STATUS *status) {
    if (!hash) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    ll_HKDF_CTX *ctx = (ll_HKDF_CTX*)SECURE_ALLOC(sizeof(ll_HKDF_CTX));
    if (!ctx) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    CF_STATUS st = ll_HKDF_Init(ctx, hash, info, info_len);
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
    if (!ctx || !ctx->hash)
        return CF_ERR_NULL_PTR;

    if (ctx->isExtracted)
        return CF_ERR_KDF_ALREADY_EXTRACTED;

    size_t hash_len = ctx->hash->digest_size;  // always PRK = hash output size

    CF_STATUS st;
    ll_HMAC_CTX hmac_ctx = {0};

    // HMAC key = salt
    const uint8_t *used_salt = salt;
    uint8_t zero_salt[CF_MAX_DEFAULT_DIGEST_SIZE] = {0};

    if (!salt || salt_len == 0) {
        used_salt = zero_salt;
        salt_len = ctx->hash->digest_size;
    }

    st = ll_HMAC_Init(&hmac_ctx, ctx->hash, used_salt, salt_len);
    if (st != CF_SUCCESS) {
        return st;
    }

    // Feed the input key material (IKM) into HMAC
    st = ll_HMAC_Update(&hmac_ctx, ikm, ikm_len);
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

    ctx->isExtracted = 1;

    return CF_SUCCESS;
}

CF_STATUS ll_HKDF_Expand(
    ll_HKDF_CTX *ctx,
    uint8_t *okm, size_t okm_len,
    const uint8_t *new_info, size_t new_info_len) {
    if (!ctx || !ctx->hash || !ctx->prk || !okm)
        return CF_ERR_NULL_PTR;

    if (okm_len == 0)
        return CF_ERR_INVALID_LEN;

    const size_t hash_len = ctx->hash->digest_size;
    const size_t max_okm = LL_HKDF_MAX_OKM(hash_len); // RFC 5869 max 255 blocks
    if (okm_len > max_okm)
        return CF_ERR_LIMIT_EXCEEDED;

    // Replace info if provided
    if (new_info) {
        ctx->info = new_info;
        ctx->info_len = new_info_len;
    }

    // Prepare for expansion
    SECURE_ZERO(ctx->prev_block, sizeof(ctx->prev_block));
    ctx->counter = 0;

    ll_HMAC_CTX hmac_ctx = {0};
    CF_STATUS st;
    size_t generated = 0;
    uint8_t block[CF_MAX_DEFAULT_HASH_BLOCK_SIZE] = {0};

    while (generated < okm_len) {
        if (ctx->counter >= LL_HKDF_MAX_BLOCKS) {
            st = CF_ERR_LIMIT_EXCEEDED;
            goto cleanup;
        }

        ctx->counter++;
        uint8_t ctr = (uint8_t)ctx->counter;

        st = ll_HMAC_Init(&hmac_ctx, ctx->hash, ctx->prk, ctx->prk_len);
        if (st != CF_SUCCESS) goto cleanup;

        // Feed previous block (full hash_len, not just truncated)
        if (ctx->counter > 1) {
            st = ll_HMAC_Update(&hmac_ctx, ctx->prev_block, hash_len);
            if (st != CF_SUCCESS) goto cleanup;
        }

        // Feed info if present
        if (ctx->info && ctx->info_len) {
            st = ll_HMAC_Update(&hmac_ctx, ctx->info, ctx->info_len);
            if (st != CF_SUCCESS) goto cleanup;
        }

        // Feed counter
        st = ll_HMAC_Update(&hmac_ctx, &ctr, 1);
        if (st != CF_SUCCESS) goto cleanup;

        st = ll_HMAC_Final(&hmac_ctx, block, hash_len);
        if (st != CF_SUCCESS) goto cleanup;

        ll_HMAC_Reset(&hmac_ctx);

        size_t to_copy = (okm_len - generated > hash_len) ? hash_len : (okm_len - generated);
        SECURE_MEMCPY(okm + generated, block, to_copy);
        generated += to_copy;

        // Save full block for next iteration
        SECURE_MEMCPY(ctx->prev_block, block, hash_len);
        SECURE_ZERO(block, sizeof(block));
    }

    st = CF_SUCCESS;

cleanup:
    ll_HMAC_Reset(&hmac_ctx);
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

    SECURE_ZERO(ctx->prev_block, sizeof(ctx->prev_block));

    ctx->hash = NULL;
    ctx->info = NULL;
    ctx->info_len = 0;
    ctx->prk_len = 0;
    ctx->counter = 0;
    ctx->info_len = 0;
    ctx->isExtracted = 0;

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

    // Clone pointer
    ctx_dest->info = ctx_src->info;
    ctx_dest->info_len = ctx_src->info_len;

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