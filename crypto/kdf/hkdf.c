/*
 * CryptoForge - hkdf.c / HKDF (HKDF-SHA-1, HKDF-SHA-2, and HKDF-SHA-3) Implementation
 * Copyright (C) 2025 0xNullll
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#include "hkdf.h"

CF_STATUS ll_HKDF_Init(ll_HKDF_CTX *ctx, const EVP_MD *md, const uint8_t *info, size_t info_len) {
    if (!ctx || !md)
        return CF_ERR_NULL_PTR; 

    // HKDF is not compatible with XOF hash functions, as per HMAC-based design rules
    if (EVP_IS_XOF(md->id))
        return CF_ERR_UNSUPPORTED;

    // nothing to write
    if (info && info_len == 0)
        return CF_ERR_INVALID_PARAM;

    SECURE_ZERO(ctx, sizeof(*ctx));

    ctx->md = md;

    if (info) {
        ctx->info = (uint8_t *)SECURE_ALLOC(info_len);
        SECURE_MEMCPY((void *)ctx->info, info, info_len);

        if (!ctx->info)
            return CF_ERR_ALLOC_FAILED;

        ctx->info_len = info_len;
    } else {
        ctx->info = NULL;
        ctx->info_len = 0;
    }

    SECURE_ZERO(ctx->prev_block, sizeof(ctx->prev_block));
    ctx->counter = 0;

    // Mark as not heap-allocated
    ctx->isHeapAlloc = 0;
    return CF_SUCCESS;
}

ll_HKDF_CTX* ll_HKDF_InitAlloc(const EVP_MD *md, const uint8_t *info, size_t info_len, CF_STATUS *status) {
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

    // Mark as heap-allocated
    ctx->isHeapAlloc = 1;
    if (status) *status = CF_SUCCESS;
    return ctx;
}

CF_STATUS ll_HKDF_Extract(
    ll_HKDF_CTX *ctx,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *ikm, size_t ikm_len) {
    if (!ctx || !ctx->md || !ikm)
        return CF_ERR_NULL_PTR;

    if (ikm_len == 0)
        return CF_ERR_INVALID_LEN;

    if (salt && salt_len == 0)
        return CF_ERR_INVALID_PARAM;

    size_t hash_len = ctx->md->digest_size;  // always PRK = hash output size

    CF_STATUS st;
    ll_HMAC_CTX *hmac_ctx = (ll_HMAC_CTX *)SECURE_ALLOC(sizeof(ll_HMAC_CTX));
    if (!hmac_ctx)
        return CF_ERR_ALLOC_FAILED;

    // Initialize HMAC with salt (or zeroed default)
    st = ll_HMAC_Init(hmac_ctx, ctx->md, salt ? salt : NULL, salt ? salt_len : 0);
    if (st != CF_SUCCESS) {
        SECURE_FREE(hmac_ctx, sizeof(ll_HMAC_CTX));
        return st;
    }

    // Feed the input key material (IKM) into HMAC
    st = ll_HMAC_Update(hmac_ctx, ikm, ikm_len);
    if (st != CF_SUCCESS) {
        ll_HMAC_Free(hmac_ctx);                     // only cleans internal buffers
        SECURE_FREE(hmac_ctx, sizeof(ll_HMAC_CTX)); // frees the struct
        return st;
    }

    // Allocate and compute PRK
    ctx->prk = (uint8_t *)SECURE_ALLOC(hash_len);
    if (!ctx->prk) {
        ll_HMAC_Free(hmac_ctx);
        SECURE_FREE(hmac_ctx, sizeof(ll_HMAC_CTX));
        return CF_ERR_ALLOC_FAILED;
    }

    st = ll_HMAC_Final(hmac_ctx, ctx->prk, hash_len);
    ll_HMAC_Free(hmac_ctx);                     // clean internal buffers
    SECURE_FREE(hmac_ctx, sizeof(ll_HMAC_CTX)); // free the struct itself
    if (st != CF_SUCCESS) {
        SECURE_FREE((void *)ctx->prk, hash_len);
        ctx->prk = NULL;
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
    uint8_t block[EVP_MAX_DEFAULT_BLOCK_SIZE];

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
        ll_HMAC_Free(hmac_ctx);

        // Copy required bytes to output
        size_t to_copy = (okm_len - generated > hash_len) ? hash_len : (okm_len - generated);
        SECURE_MEMCPY(okm + generated, block, to_copy);
        generated += to_copy;

        // Save current block for next iteration
        SECURE_MEMCPY(ctx->prev_block, block, hash_len);
        prev_block_len = hash_len;
    }

    st = CF_SUCCESS;

cleanup:
    ll_HMAC_Free(hmac_ctx);
    SECURE_FREE(hmac_ctx, sizeof(ll_HMAC_CTX));
    return st;
}

CF_STATUS ll_HKDF_Free(ll_HKDF_CTX *ctx) {
    if (!ctx)
        return CF_ERR_NULL_PTR;

    if (ctx->prk) {
        if (ctx->prk_len == 0)
            return CF_ERR_CTX_CORRUPT;

        SECURE_ZERO(ctx->prk, ctx->prk_len);
        SECURE_FREE(ctx->prk, ctx->prk_len);
    }

    if (ctx->info) {
        if (ctx->info_len == 0)
            return CF_ERR_CTX_CORRUPT;

        SECURE_ZERO(ctx->info, ctx->info_len);
        SECURE_FREE(ctx->info, ctx->info_len);
    }

    SECURE_ZERO(ctx->prev_block, sizeof(ctx->prev_block));

    // clear high-level data
    SECURE_ZERO(ctx, sizeof(*ctx));

    return CF_SUCCESS;
}

CF_STATUS ll_HKDF_FreeAlloc(ll_HKDF_CTX **p_ctx) {
    if (!p_ctx || !*p_ctx)
        return CF_ERR_NULL_PTR;

    ll_HKDF_CTX *ctx = *p_ctx;
    int wasHeapAlloc = ctx->isHeapAlloc;  // save flag

    CF_STATUS st = ll_HKDF_Free(ctx);
    if (st != CF_SUCCESS)
        return st;

    if (wasHeapAlloc)
        SECURE_FREE(ctx, sizeof(*ctx));   // free only if heap-allocated

    *p_ctx = NULL;  // nullify caller pointer

    return CF_SUCCESS;
}

// typedef struct _ll_HKDF_CTX {
//     const EVP_MD *md;         // Low-level hash descriptor

//     uint8_t *prk;             // Pseudorandom key from Extract (constant HMAC key)
//     size_t prk_len;           // Length of PRK (HashLen)

//     uint8_t prev_block[EVP_MAX_DEFAULT_DIGEST_SIZE]; // Last HMAC output (Ti), max hash size
//     uint8_t counter;                                 // Block counter (1..255)

//     uint8_t *info;             // Optional context info
//     size_t info_len;           // Length of info

//     int isHeapAlloc;           // 1 if allocated by library (heap), 0 if user stack
// } ll_HKDF_CTX;

CF_STATUS ll_HKDF_CloneCtx(ll_HKDF_CTX *ctx_dest, const ll_HKDF_CTX *ctx_src) {
    if (!ctx_dest || !ctx_src) return CF_ERR_NULL_PTR;

    // Copy top-level context first (fixed-size parts only)
    ll_HKDF_CTX tmp = *ctx_src; // shallow copy
    SECURE_ZERO(ctx_dest, sizeof(*ctx_dest));
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