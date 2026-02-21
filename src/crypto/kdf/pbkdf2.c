/*
 * CryptoForge - pbkdf2.c / PBKDF2 (PBKDF2-HMAC-SHA1, SHA2, SHA3) Implementation
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
#include "../../include/crypto/pbkdf2.h"

CF_STATUS ll_PBKDF2_Init(
    ll_PBKDF2_CTX *ctx,
    const CF_HASH *hash,
    const uint8_t *password, size_t password_len) {
    if (!ctx || !hash)
        return CF_ERR_NULL_PTR; 

    // PBKDF2 is not compatible with XOF hash functions, as per HMAC-based design rules
    if (CF_IS_XOF(hash->id))
        return CF_ERR_UNSUPPORTED;

    ll_PBKDF2_Reset(ctx);
        
    ctx->hash = hash;

    ctx->password = password;
    ctx->password_len = password_len;

    return CF_SUCCESS;
}

ll_PBKDF2_CTX* ll_PBKDF2_InitAlloc(
    const CF_HASH *hash,
    const uint8_t *password, size_t password_len,
    CF_STATUS *status) {
    if (!hash) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    ll_PBKDF2_CTX *ctx = (ll_PBKDF2_CTX*)SECURE_ALLOC(sizeof(ll_PBKDF2_CTX));
    if (!ctx) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    CF_STATUS st = ll_PBKDF2_Init(ctx, hash, password, password_len);
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
    if (!ctx)
        return CF_ERR_NULL_PTR;

    if (!ctx->hash)
        return CF_ERR_CTX_UNINITIALIZED;

    if (ctx->isExtracted)
        return CF_ERR_KDF_ALREADY_EXTRACTED;

    size_t hash_len = ctx->hash->digest_size;  // PRK length = hash output size
    CF_STATUS st;

    ll_HMAC_CTX hmac_ctx = {0};

    if (salt) {
        ctx->salt = (uint8_t *)SECURE_ALLOC(salt_len);
        SECURE_MEMCPY((void *)ctx->salt, salt, salt_len);

        if (!ctx->salt)
            return CF_ERR_ALLOC_FAILED;

        ctx->salt_len = salt_len;
    }

    // HMAC key = password
    st = ll_HMAC_Init(&hmac_ctx, ctx->hash, ctx->password, ctx->password_len);
    if (st != CF_SUCCESS)
        return st;

    st = ll_HMAC_Update(&hmac_ctx, ctx->salt, ctx->salt_len);
    
    if (st != CF_SUCCESS) {
        ll_HMAC_Reset(&hmac_ctx);
        return st;
    }

    // Compute PRK and store in context
    st = ll_HMAC_Final(&hmac_ctx, ctx->prev_block, hash_len);
    ll_HMAC_Reset(&hmac_ctx);
    if (st != CF_SUCCESS) {
        SECURE_ZERO(ctx->prev_block, sizeof(ctx->prev_block));
        return st;
    }

    // Prepare for Expand: first block index = 1
    ctx->block_index = 1;
    ctx->generated_len = 0;

    ctx->isExtracted = 1;

    return CF_SUCCESS;
}

CF_STATUS ll_PBKDF2_Expand(
    ll_PBKDF2_CTX *ctx,
    uint8_t *dk, size_t dk_len,
    const size_t iterations) {
    if (!ctx || !dk)
        return CF_ERR_NULL_PTR;

    if (!ctx->hash)
        return CF_ERR_CTX_UNINITIALIZED;

    if (iterations > LL_PBKDF2_MAX_ITERATION)
        return CF_ERR_INVALID_LEN;

    // if (iterations < LL_PBKDF2_MIN_ITERATIONS || iterations > LL_PBKDF2_MAX_ITERATION)
    //     return CF_ERR_INVALID_LEN;

    size_t hash_len = ctx->hash->digest_size;
    size_t l = (dk_len + hash_len - 1) / hash_len;  // ceil division
    size_t r = dk_len - (l - 1) * hash_len;

    uint8_t T[CF_MAX_DEFAULT_DIGEST_SIZE];
    uint8_t U[CF_MAX_DEFAULT_DIGEST_SIZE];
    size_t generated = 0;
    CF_STATUS st;

    // --- Precompute HMAC base with password ---
    ll_HMAC_CTX base_hmac = {0};
    st = ll_HMAC_Init(&base_hmac, ctx->hash, ctx->password, ctx->password_len);
    if (st != CF_SUCCESS)
        return st;

    // Allocate working ctx once
    ll_HMAC_CTX work_hmac = {0};
    work_hmac.key     = base_hmac.key;
    work_hmac.key_len = base_hmac.key_len;
    work_hmac.hash    = base_hmac.hash;

    for (uint32_t block = 1; block <= l; block++) {
        // --- U1 = HMAC(password, salt || INT(block)) ---
        SECURE_MEMCPY(work_hmac.ipad_ctx, base_hmac.ipad_ctx, ctx->hash->ctx_size);
        SECURE_MEMCPY(work_hmac.opad_ctx, base_hmac.opad_ctx, ctx->hash->ctx_size);
        work_hmac.out_len = 0;
        work_hmac.isFinalized = 0;

        st = ll_HMAC_Update(&work_hmac, ctx->salt, ctx->salt_len);
        if (st != CF_SUCCESS) goto cleanup;

        // Serialize block counter to 4-byte big-endian form
        uint8_t block_index[4];
        STORE32BE(block_index, block);

        st = ll_HMAC_Update(&work_hmac, block_index, 4);
        if (st != CF_SUCCESS) goto cleanup;

        st = ll_HMAC_Final(&work_hmac, U, hash_len);
        if (st != CF_SUCCESS) goto cleanup;

        SECURE_MEMCPY(T, U, hash_len);

        // --- iterations j = 2..c ---
        for (size_t j = 2; j <= iterations; j++) {
            // Only reset internal digest state, keep key/pads
            SECURE_MEMCPY(work_hmac.ipad_ctx, base_hmac.ipad_ctx, ctx->hash->ctx_size);
            SECURE_MEMCPY(work_hmac.opad_ctx, base_hmac.opad_ctx, ctx->hash->ctx_size);
            work_hmac.out_len = 0;
            work_hmac.isFinalized = 0;

            st = ll_HMAC_Update(&work_hmac, U, hash_len);
            if (st != CF_SUCCESS) goto cleanup;

            st = ll_HMAC_Final(&work_hmac, U, hash_len);
            if (st != CF_SUCCESS) goto cleanup;

            for (size_t k = 0; k < hash_len; k++)
                T[k] ^= U[k];
        }

        // Copy T into derived key
        size_t to_copy = (block == l) ? r : hash_len;
        SECURE_MEMCPY(dk + generated, T, to_copy);
        generated += to_copy;
    }

    st = CF_SUCCESS;

cleanup:
    SECURE_ZERO(T, sizeof(T));
    SECURE_ZERO(U, sizeof(U));
    ll_HMAC_Reset(&base_hmac);
    ll_HMAC_Reset(&work_hmac);
    return st;
}

CF_STATUS ll_PBKDF2_Reset(ll_PBKDF2_CTX *ctx) {
    if (!ctx)
        return CF_ERR_NULL_PTR;

    if (ctx->salt) {
        if (ctx->salt_len == 0)
            return CF_ERR_CTX_CORRUPT;
        SECURE_FREE(ctx->salt, ctx->salt_len);
    }

    SECURE_ZERO(ctx->prev_block, sizeof(ctx->prev_block));

    ctx->hash = NULL;
    ctx->password = NULL;
    ctx->password_len = 0;
    ctx->iterations = 0;
    ctx->dk_len = 0;
    ctx->block_index = 0;
    ctx->generated_len = 0;
    ctx->isExtracted = 0;

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
    if (!ctx->hash) return 0;

    // Convert digest size to bits
    double hash_bits = (double)(ctx->hash->digest_size * 8);

    // Formula: iterations ≈ 2.4e9 * hash_bits^(-1.64)
    double iter = 2.4e9 * pow(hash_bits, -1.64);

    // Clamp to at least 1 iteration
    if (iter < 1.0) iter = 1.0;

    return (uint32_t)(iter + 0.5); // round to nearest integer
}

CF_STATUS ll_PBKDF2_CloneCtx(ll_PBKDF2_CTX *ctx_dest,
                            const ll_PBKDF2_CTX *ctx_src) {
    if (!ctx_dest || !ctx_src)
        return CF_ERR_NULL_PTR;

    // Temporary shallow copy
    ll_PBKDF2_CTX tmp = *ctx_src;

    // Reset destination (zero + free owned buffers if any)
    ll_PBKDF2_Reset(ctx_dest);

    // Copy fixed-size and pointer fields
    SECURE_MEMCPY(ctx_dest, &tmp, sizeof(*ctx_dest));

    // Cloned context does not own top-level allocation by default
    ctx_dest->isHeapAlloc = 0;

    // ---- Clone salt ----
    if (ctx_src->salt && ctx_src->salt_len > 0) {
        ctx_dest->salt = (uint8_t *)SECURE_ALLOC(ctx_src->salt_len);
        if (!ctx_dest->salt)
            return CF_ERR_ALLOC_FAILED;

        SECURE_MEMCPY(ctx_dest->salt,
                      ctx_src->salt,
                      ctx_src->salt_len);
        ctx_dest->salt_len = ctx_src->salt_len;
    }

    // ---- Clone password ----
    ctx_dest->password = ctx_src->password;
    ctx_dest->password_len = ctx_src->password_len;

    return CF_SUCCESS;
}

ll_PBKDF2_CTX *ll_PBKDF2_CloneCtxAlloc(const ll_PBKDF2_CTX *ctx_src,
                                      CF_STATUS *status) {
    if (!ctx_src) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    // Allocate top-level context
    ll_PBKDF2_CTX *dst = (ll_PBKDF2_CTX *)SECURE_ALLOC(sizeof(ll_PBKDF2_CTX));
    if (!dst) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Clone into newly allocated context
    CF_STATUS st = ll_PBKDF2_CloneCtx(dst, ctx_src);
    if (status) *status = st;

    if (st != CF_SUCCESS) {
        SECURE_FREE(dst, sizeof(*dst));
        return NULL;
    }

    // Library owns this allocation
    dst->isHeapAlloc = 1;
    return dst;
}