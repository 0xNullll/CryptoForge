/*
 * CryptoForge - hmac.c / HMAC (HMAC-SHA-1, HMAC-SHA-2, and HMAC-SHA-3) Implementation
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against WyChaProof test vectors. No hardware optimizations. Use with caution.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#include "../../include/crypto/hmac.h"

CF_STATUS ll_HMAC_Init(ll_HMAC_CTX *ctx, const CF_MD *md, const uint8_t *key, size_t key_len) {
    if (!ctx || !md || !key)
        return CF_ERR_NULL_PTR;

    if (CF_IS_XOF(md->id))
        return CF_ERR_UNSUPPORTED;

    if (md->block_size == 0 || md->block_size > CF_MAX_DEFAULT_BLOCK_SIZE)
        return CF_ERR_UNSUPPORTED;

    if (ctx->isHeapAlloc != 0 && ctx->isHeapAlloc != 1)
        return CF_ERR_CTX_UNINITIALIZED;

    ll_HMAC_Reset(ctx);

    ctx->md = md;
    ctx->out_len = md->digest_size != 0 ? md->digest_size : md->default_out_len;

    // normalize key
    if (key_len > md->block_size) {
        if (!md->hash_init_fn(ctx->ipad_ctx, NULL) ||
            !md->hash_update_fn(ctx->ipad_ctx, key, key_len) ||
            !md->hash_final_fn(ctx->ipad_ctx, ctx->key, md->digest_size)) {
            goto cleanup;
        }
        if (md->hash_squeeze_fn && !md->hash_squeeze_fn(ctx->ipad_ctx, ctx->key, md->digest_size))
            goto cleanup;

        key_len = (md->digest_size != 0) ? md->digest_size : md->default_out_len;
    } else {
        // copy short key
        SECURE_MEMCPY(ctx->key, key, key_len);
    }

    if (key_len < md->block_size)
        SECURE_MEMSET(ctx->key + key_len, 0, md->block_size - key_len);
    ctx->key_len = md->block_size;

    // apply XOR pads
    uint8_t ipad[CF_MAX_DEFAULT_BLOCK_SIZE], opad[CF_MAX_DEFAULT_BLOCK_SIZE];
    for (size_t i = 0; i < md->block_size; i++) {
        ipad[i] = ctx->key[i] ^ 0x36;
        opad[i] = ctx->key[i] ^ 0x5c;
    }

    // init hash contexts and feed pads
    if (!md->hash_init_fn(ctx->ipad_ctx, NULL) ||
        !md->hash_init_fn(ctx->opad_ctx, NULL))
        goto cleanup;

    if (!md->hash_update_fn(ctx->ipad_ctx, ipad, md->block_size) ||
        !md->hash_update_fn(ctx->opad_ctx, opad, md->block_size))
        goto cleanup;

    SECURE_ZERO(ipad, md->block_size);
    SECURE_ZERO(opad, md->block_size);
    return CF_SUCCESS;

cleanup:
    SECURE_ZERO(ctx->ipad_ctx, md->ctx_size);
    SECURE_ZERO(ctx->opad_ctx, md->ctx_size);
    return CF_ERR_CTX_CORRUPT;
}

ll_HMAC_CTX* ll_HMAC_InitAlloc(const CF_MD *md, const uint8_t *key, size_t key_len, CF_STATUS *status) {
    if (!md) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    ll_HMAC_CTX *ctx = (ll_HMAC_CTX *)SECURE_ALLOC(sizeof(ll_HMAC_CTX));
    if (!ctx) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    CF_STATUS st = ll_HMAC_Init(ctx, md, key, key_len);
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
    if (!ctx || !ctx->md || !data)
        return CF_ERR_NULL_PTR;

    if (ctx->isFinalized) 
        return CF_ERR_HASH_FINALIZED;

    if (!ctx->md->hash_update_fn(ctx->ipad_ctx, data, data_len))
        return CF_ERR_CTX_CORRUPT;

    return CF_SUCCESS;
}

CF_STATUS ll_HMAC_Final(ll_HMAC_CTX *ctx, uint8_t *digest, size_t digest_len) {
    if (!ctx || !ctx->md || !digest)
        return CF_ERR_NULL_PTR;

    if (digest_len == 0 && ctx->out_len == 0)
        return CF_ERR_INVALID_LEN; // nothing to write

    if (ctx->isFinalized) 
        return CF_ERR_HASH_FINALIZED;

    CF_STATUS ret = CF_SUCCESS;

    const size_t hash_len = ctx->md->digest_size;
    uint8_t inner_hash[CF_MAX_DEFAULT_DIGEST_SIZE] = {0};

    // compute inner hash
    if (!ctx->md->hash_final_fn(ctx->ipad_ctx, inner_hash, ctx->md->digest_size)) {
        ret = CF_ERR_CTX_CORRUPT;
        goto cleanup;
    }

    // For SHA3 variants that require squeezing
    if (ctx->md->hash_squeeze_fn && CF_IS_KECCAK(ctx->md->id)) {
        if (!ctx->md->hash_squeeze_fn(ctx->ipad_ctx, inner_hash, ctx->md->digest_size)) {
            ret = CF_ERR_CTX_CORRUPT;
            goto cleanup;
        }
    }

    // feed inner hash into opad context
    if (!ctx->md->hash_update_fn(ctx->opad_ctx, inner_hash, ctx->md->digest_size)) {
        ret = CF_ERR_CTX_CORRUPT;
        goto cleanup;
    }

    // compute final HMAC
    if (!ctx->md->hash_final_fn(ctx->opad_ctx, digest, hash_len)) {
        ret = CF_ERR_CTX_CORRUPT;
        goto cleanup;
    }

    // For SHA3 variants that require squeezing
    if (ctx->md->hash_squeeze_fn && CF_IS_KECCAK(ctx->md->id)) {
        if (!ctx->md->hash_squeeze_fn(ctx->opad_ctx, digest, hash_len)) {
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
    const CF_MD *md,
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    const uint8_t *expected_tag, size_t expected_tag_len) {
    if (!md || !key || !data || !expected_tag)
        return CF_ERR_NULL_PTR;

    CF_STATUS status = CF_SUCCESS;

    uint8_t tag[CF_MAX_DEFAULT_DIGEST_SIZE] = {0};
    ll_HMAC_CTX ctx = {0};

    // Initialize context
    status = ll_HMAC_Init(&ctx, md, key, key_len);
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
    if (!ctx || !ctx->md)
        return CF_ERR_NULL_PTR;

    int wasHeapAlloc = ctx->isHeapAlloc;

    SECURE_ZERO(ctx->ipad_ctx, ctx->md->ctx_size);
    SECURE_ZERO(ctx->opad_ctx, ctx->md->ctx_size);

    // Zero key material and reset fields
    SECURE_ZERO(ctx->key, sizeof(ctx->key));
    ctx->key_len = 0;
    ctx->out_len = 0;
    ctx->isFinalized = 0;
    ctx->isHeapAlloc = wasHeapAlloc;

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

    // Copy MD pointer
    ctx_dest->md = ctx_src->md;

    // Allocate and copy inner/outer contexts
    if (ctx_src->md && ctx_src->md->ctx_size > 0) {
        SECURE_MEMCPY(ctx_dest->ipad_ctx, ctx_src->ipad_ctx, ctx_src->md->ctx_size);
        SECURE_MEMCPY(ctx_dest->opad_ctx, ctx_src->opad_ctx, ctx_src->md->ctx_size);
    }

    // Copy key and metadata
    SECURE_MEMCPY(ctx_dest->key, ctx_src->key, sizeof(ctx_dest->key));

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