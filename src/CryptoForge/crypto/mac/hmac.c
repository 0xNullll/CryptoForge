/*
 * CryptoForge - hmac.c / HMAC (HMAC-SHA-1, HMAC-SHA-2, and HMAC-SHA-3) Implementation
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

#include "../../include/crypto/hmac.h"

CF_STATUS ll_HMAC_Init(ll_HMAC_CTX *ctx, const CF_HASH *hash, const uint8_t *key, size_t key_len) {
    if (!ctx || !hash || !key)
        return CF_ERR_NULL_PTR;

    if (CF_IS_XOF(hash->id))
        return CF_ERR_UNSUPPORTED;

    if (hash->block_size == 0 || hash->block_size > CF_MAX_DEFAULT_HASH_BLOCK_SIZE)
        return CF_ERR_UNSUPPORTED;

    ll_HMAC_Reset(ctx);

    ctx->hash = hash;
    ctx->out_len = hash->digest_size ? hash->digest_size : hash->default_out_len;
    ctx->isFinalized = 0;

    size_t digest_size = ctx->out_len;

    // Hash the key if too long
    uint8_t key_block[CF_MAX_DEFAULT_HASH_BLOCK_SIZE] = {0};
    if (key_len > hash->block_size) {
        uint8_t digest[CF_MAX_DEFAULT_DIGEST_SIZE];
        if (!hash->hash_init_fn(ctx->ipad_ctx, NULL) ||
            !hash->hash_update_fn(ctx->ipad_ctx, key, key_len) ||
            !hash->hash_final_fn(ctx->ipad_ctx, digest)) {
            return CF_ERR_CTX_CORRUPT;
        }
        SECURE_MEMCPY(key_block, digest, digest_size);
        key_len = digest_size;
    } else {
        SECURE_MEMCPY(key_block, key, key_len);
    }

    // Zero-pad to block size
    if (key_len < hash->block_size)
        SECURE_ZERO(key_block + key_len, hash->block_size - key_len);

    ctx->key_len = hash->block_size;
    ctx->key     = key_block;

    // Build ipad/opad arrays
    uint8_t ipad[CF_MAX_DEFAULT_HASH_BLOCK_SIZE];
    uint8_t opad[CF_MAX_DEFAULT_HASH_BLOCK_SIZE];

    for (size_t i = 0; i < hash->block_size; i++) {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    // Init hash contexts and feed pads
    if (!hash->hash_init_fn(ctx->ipad_ctx, NULL) ||
        !hash->hash_init_fn(ctx->opad_ctx, NULL))
        goto cleanup;

    if (!hash->hash_update_fn(ctx->ipad_ctx, ipad, hash->block_size) ||
        !hash->hash_update_fn(ctx->opad_ctx, opad, hash->block_size))
        goto cleanup;

    // Clean sensitive temporary buffers
    SECURE_ZERO(key_block, hash->block_size);
    SECURE_ZERO(ipad, hash->block_size);
    SECURE_ZERO(opad, hash->block_size);

    return CF_SUCCESS;

cleanup:
    SECURE_ZERO(ctx->ipad_ctx, hash->ctx_size);
    SECURE_ZERO(ctx->opad_ctx, hash->ctx_size);
    return CF_ERR_CTX_CORRUPT;
}

ll_HMAC_CTX* ll_HMAC_InitAlloc(const CF_HASH *hash, const uint8_t *key, size_t key_len, CF_STATUS *status) {
    if (!hash) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    ll_HMAC_CTX *ctx = (ll_HMAC_CTX *)SECURE_ALLOC(sizeof(ll_HMAC_CTX));
    if (!ctx) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    CF_STATUS st = ll_HMAC_Init(ctx, hash, key, key_len);
    if (st != CF_SUCCESS) {
        SECURE_FREE(ctx, sizeof(ll_HMAC_CTX));
        if (status) *status = st;
        return NULL;
    }

    ctx->isHeapAlloc = 1;
    if (status) *status = CF_SUCCESS;
    return ctx;
}

CF_STATUS ll_HMAC_Update(ll_HMAC_CTX *ctx, const uint8_t *data, size_t data_len) {
    if (!ctx || !ctx->hash || !data)
        return CF_ERR_NULL_PTR;

    if (ctx->isFinalized) 
        return CF_ERR_HASH_FINALIZED;

    if (!ctx->hash->hash_update_fn(ctx->ipad_ctx, data, data_len))
        return CF_ERR_CTX_CORRUPT;

    return CF_SUCCESS;
}

CF_STATUS ll_HMAC_Final(ll_HMAC_CTX *ctx, uint8_t *digest, size_t digest_len) {
    if (!ctx || !ctx->hash || !digest)
        return CF_ERR_NULL_PTR;

    if (digest_len == 0 && ctx->out_len == 0)
        return CF_ERR_INVALID_LEN; // nothing to write

    if (ctx->isFinalized) 
        return CF_ERR_HASH_FINALIZED;

    CF_STATUS ret = CF_SUCCESS;

    const size_t hash_len = MIN(digest_len, ctx->hash->digest_size);
    uint8_t inner_hash[CF_MAX_DEFAULT_DIGEST_SIZE] = {0};

    // compute inner hash
    if (!ctx->hash->hash_final_fn(ctx->ipad_ctx, inner_hash)) {
        ret = CF_ERR_CTX_CORRUPT;
        goto cleanup;
    }

    // For SHA3 variants that require squeezing
    if (ctx->hash->hash_squeeze_fn && CF_IS_KECCAK(ctx->hash->id)) {
        if (!ctx->hash->hash_squeeze_fn(ctx->ipad_ctx, inner_hash, ctx->hash->digest_size)) {
            ret = CF_ERR_CTX_CORRUPT;
            goto cleanup;
        }
    }

    // feed inner hash into opad context
    if (!ctx->hash->hash_update_fn(ctx->opad_ctx, inner_hash, ctx->hash->digest_size)) {
        ret = CF_ERR_CTX_CORRUPT;
        goto cleanup;
    }

    // compute final HMAC
    if (!ctx->hash->hash_final_fn(ctx->opad_ctx, digest)) {
        ret = CF_ERR_CTX_CORRUPT;
        goto cleanup;
    }

    // For SHA3 variants that require squeezing
    if (ctx->hash->hash_squeeze_fn && CF_IS_KECCAK(ctx->hash->id)) {
        if (!ctx->hash->hash_squeeze_fn(ctx->opad_ctx, digest, hash_len)) {
            ret = CF_ERR_CTX_CORRUPT;
            goto cleanup;
        }
    }

    ctx->isFinalized = 1;

cleanup:
    SECURE_ZERO(inner_hash, sizeof(inner_hash));
    return ret;
}

CF_STATUS ll_HMAC_Verify(
    const CF_HASH *hash,
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    const uint8_t *expected_tag, size_t expected_tag_len) {
    if (hash || !key || !data || !expected_tag)
        return CF_ERR_NULL_PTR;

    CF_STATUS status = CF_SUCCESS;

    uint8_t tag[CF_MAX_DEFAULT_DIGEST_SIZE] = {0};
    ll_HMAC_CTX ctx = {0};

    // Initialize context
    status = ll_HMAC_Init(&ctx, hash, key, key_len);
    if (status != CF_SUCCESS) goto cleanup;

    // Update with data
    status = ll_HMAC_Update(&ctx, data, data_len);
    if (status != CF_SUCCESS) goto cleanup;

    // Finalize
    status = ll_HMAC_Final(&ctx, tag, expected_tag_len);
    if (status != CF_SUCCESS) goto cleanup;

    // Constant-time comparison
    status = SECURE_MEM_EQUAL(tag, expected_tag, expected_tag_len) ? CF_SUCCESS : CF_ERR_MAC_VERIFY;

cleanup:
    ll_HMAC_Reset(&ctx);
    SECURE_ZERO(tag, sizeof(tag));
    return status;
}

CF_STATUS ll_HMAC_Reset(ll_HMAC_CTX *ctx) {
    if (!ctx || !ctx->hash)
        return CF_ERR_NULL_PTR;

    SECURE_ZERO(ctx->ipad_ctx, ctx->hash->ctx_size);
    SECURE_ZERO(ctx->opad_ctx, ctx->hash->ctx_size);

    // Zero key material and reset fields
    ctx->key         = NULL;
    ctx->key_len     = 0;
    ctx->out_len     = 0;
    ctx->isFinalized = 0;

    return CF_SUCCESS;
}

CF_STATUS ll_HMAC_Free(ll_HMAC_CTX **p_ctx) {
    if (!p_ctx || !*p_ctx)
        return CF_ERR_NULL_PTR;

    ll_HMAC_CTX *ctx = *p_ctx;
    int wasHeapAlloc = ctx->isHeapAlloc;  // save flag

    // Reuse Free to clean internals
    ll_HMAC_Reset(ctx);

    // Free the outer struct if heap-allocated
    if (wasHeapAlloc)
        SECURE_FREE(ctx, sizeof(ll_HMAC_CTX));

    return CF_SUCCESS;
}

CF_STATUS ll_HMAC_CloneCtx(ll_HMAC_CTX *ctx_dest, const ll_HMAC_CTX *ctx_src) {
    if (!ctx_dest || !ctx_src)
        return CF_ERR_NULL_PTR;

    // Zero the destination first
    ll_HMAC_Reset(ctx_dest);

    // Copy hash pointer
    ctx_dest->hash = ctx_src->hash;

    // Allocate and copy inner/outer contexts
    if (ctx_src->hash && ctx_src->hash->ctx_size > 0) {
        SECURE_MEMCPY(ctx_dest->ipad_ctx, ctx_src->ipad_ctx, ctx_src->hash->ctx_size);
        SECURE_MEMCPY(ctx_dest->opad_ctx, ctx_src->opad_ctx, ctx_src->hash->ctx_size);
    }

    ctx_dest->key         = ctx_src->key;
    ctx_dest->key_len     = ctx_src->key_len;
    ctx_dest->out_len     = ctx_src->out_len;
    ctx_dest->isFinalized = ctx_src->isFinalized;
    ctx_dest->isHeapAlloc = 0; // dst is “new”, caller owns it

    return CF_SUCCESS;
}

ll_HMAC_CTX *ll_HMAC_CloneCtxAlloc(const ll_HMAC_CTX *ctx_src, CF_STATUS *status) {
    if (!ctx_src) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    // Allocate the destination context
    ll_HMAC_CTX *ctx_dest = (ll_HMAC_CTX *)SECURE_ALLOC(sizeof(ll_HMAC_CTX));
    if (!ctx_dest) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Use the in-place clone function
    CF_STATUS ret = ll_HMAC_CloneCtx(ctx_dest, ctx_src);
    if (ret != CF_SUCCESS) {
        SECURE_FREE(ctx_dest, sizeof(ll_HMAC_CTX));
        return NULL;
    }

    ctx_dest->isHeapAlloc = 1; // library owns this memory

    return ctx_dest;
}