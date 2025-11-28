#include "hmac.h"

TCLIB_STATUS ll_HMAC_Init(ll_HMAC_CTX *ctx, const EVP_MD *md, const uint8_t *key, size_t key_len) {
    if (!ctx || !md || !key)
        return TCLIB_ERR_NULL_PTR;

    if (key_len == 0)
        return TCLIB_ERR_INVALID_LEN;

    if (EVP_IS_XOF(md->id))
        return TCLIB_ERR_UNSUPPORTED;

    if (md->block_size == 0 || md->block_size > EVP_MAX_DEFAULT_BLOCK_SIZE)
        return TCLIB_ERR_UNSUPPORTED;

    ctx->md = md;
    ctx->out_len = md->digest_size != 0 ? md->digest_size : md->default_out_len;

    // allocate low-level internal contexts
    ctx->ipad_ctx = SECURE_ALLOC(md->ctx_size);
    if (!ctx->ipad_ctx)
        return TCLIB_ERR_ALLOC_FAILED;

    ctx->opad_ctx = SECURE_ALLOC(md->ctx_size);
    if (!ctx->opad_ctx) {
        SECURE_FREE(ctx->ipad_ctx, md->ctx_size);
        return TCLIB_ERR_ALLOC_FAILED;
    }

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
    uint8_t ipad[EVP_MAX_DEFAULT_BLOCK_SIZE], opad[EVP_MAX_DEFAULT_BLOCK_SIZE];
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

    ctx->isHeapAlloc = 0;
    ctx->isFinalized = 0;
    return TCLIB_SUCCESS;

cleanup:
    if (ctx->ipad_ctx) {
        SECURE_ZERO(ctx->ipad_ctx, md->ctx_size);
        SECURE_FREE(ctx->ipad_ctx, md->ctx_size);
    }

    if (ctx->opad_ctx) {
        SECURE_ZERO(ctx->opad_ctx, md->ctx_size);
        SECURE_FREE(ctx->opad_ctx, md->ctx_size);
    }

    return TCLIB_ERR_CTX_CORRUPT;
}

ll_HMAC_CTX* ll_HMAC_InitAlloc(const EVP_MD *md, const uint8_t *key, size_t key_len, TCLIB_STATUS *status) {
    if (!md) {
        if (status) *status = TCLIB_ERR_NULL_PTR;
        return NULL;
    }

    ll_HMAC_CTX *ctx = CREATE_CTX(ll_HMAC_CTX);
    if (!ctx) {
        if (status) *status = TCLIB_ERR_ALLOC_FAILED;
        return NULL;
    }

    TCLIB_STATUS st = ll_HMAC_Init(ctx, md, key, key_len);
    if (st != TCLIB_SUCCESS) {
        DESTROY_CTX(ctx, ll_HMAC_CTX);
        if (status) *status = st;
        return NULL;
    }

    ctx->isHeapAlloc = 1;
    if (status) *status = TCLIB_SUCCESS;
    return ctx;
}

TCLIB_STATUS ll_HMAC_Update(ll_HMAC_CTX *ctx, const uint8_t *data, size_t data_len) {
    if (!ctx || !ctx->md || !ctx->ipad_ctx || !data)
        return TCLIB_ERR_NULL_PTR;

    if (data_len == 0)
        return TCLIB_ERR_INVALID_LEN;

    if (!ctx->md->hash_update_fn(ctx->ipad_ctx, data, data_len))
        return TCLIB_ERR_CTX_CORRUPT;

    return TCLIB_SUCCESS;
}

TCLIB_STATUS ll_HMAC_Final(ll_HMAC_CTX *ctx, uint8_t *digest, size_t digest_len) {
    if (!ctx || !ctx->md || !ctx->ipad_ctx || !ctx->opad_ctx)
        return TCLIB_ERR_NULL_PTR;

    size_t final_len = (digest_len != 0) ? digest_len : ctx->out_len;
    if (final_len > ctx->out_len) final_len = ctx->out_len; // clamp

    // compute inner hash
    uint8_t inner_hash[EVP_MAX_DEFAULT_DIGEST_SIZE];
    if (!ctx->md->hash_final_fn(ctx->ipad_ctx, inner_hash, ctx->md->digest_size))
        return TCLIB_ERR_CTX_CORRUPT;

    // feed inner hash into opad context
    if (!ctx->md->hash_update_fn(ctx->opad_ctx, inner_hash, ctx->md->digest_size))
        return TCLIB_ERR_CTX_CORRUPT;

    // compute final HMAC
    if (!ctx->md->hash_final_fn(ctx->opad_ctx, digest, final_len))
        return TCLIB_ERR_CTX_CORRUPT;

    SECURE_ZERO(inner_hash, sizeof(inner_hash));
    ctx->isFinalized = 1;
    return TCLIB_SUCCESS;
}

TCLIB_STATUS ll_HMAC_Free(ll_HMAC_CTX *ctx) {
    if (!ctx) return TCLIB_ERR_NULL_PTR;

    if (ctx->ipad_ctx && ctx->md) {
    SECURE_ZERO(ctx->ipad_ctx, ctx->md->ctx_size);
    SECURE_FREE(ctx->ipad_ctx, ctx->md->ctx_size);
    }

    if (ctx->opad_ctx && ctx->md) {
        SECURE_ZERO(ctx->opad_ctx, ctx->md->ctx_size);
        SECURE_FREE(ctx->opad_ctx, ctx->md->ctx_size);
    }

    if (ctx->isHeapAlloc) DESTROY_CTX(ctx, ll_HMAC_CTX);

    return TCLIB_SUCCESS;
}

TCLIB_STATUS ll_HMAC_Reset(ll_HMAC_CTX *ctx) {
    if (!ctx || !ctx->md || !ctx->ipad_ctx || !ctx->opad_ctx) return TCLIB_ERR_NULL_PTR;

    // re-apply XOR pads
    uint8_t ipad[EVP_MAX_DEFAULT_BLOCK_SIZE], opad[EVP_MAX_DEFAULT_BLOCK_SIZE];
    for (size_t i = 0; i < ctx->md->block_size; i++) {
        ipad[i] = ctx->key[i] ^ 0x36;
        opad[i] = ctx->key[i] ^ 0x5c;
    }

    // reset low-level hash contexts
    if (!ctx->md->hash_init_fn(ctx->ipad_ctx, NULL) ||
        !ctx->md->hash_init_fn(ctx->opad_ctx, NULL)) return TCLIB_ERR_BAD_STATE;

    if (!ctx->md->hash_update_fn(ctx->ipad_ctx, ipad, ctx->md->block_size) ||
        !ctx->md->hash_update_fn(ctx->opad_ctx, opad, ctx->md->block_size)) return TCLIB_ERR_BAD_STATE;

    SECURE_ZERO(ipad, ctx->md->block_size);
    SECURE_ZERO(opad, ctx->md->block_size);

    ctx->out_len = ctx->md->digest_size != 0 ? ctx->md->digest_size : ctx->md->default_out_len;
    ctx->isFinalized = 0;
    return TCLIB_SUCCESS;
}

TCLIB_API TCLIB_STATUS ll_HMAC_CloneCtx(ll_HMAC_CTX *ctx_dest, const ll_HMAC_CTX *ctx_src) {
    if (!ctx_dest || !ctx_src)
        return TCLIB_ERR_NULL_PTR;

    ctx_dest->md = ctx_src->md;

    TCLIB_STATUS status;

    // Allocate and clone inner hash context
    ctx_dest->ipad_ctx = EVP_HashCloneCtxAlloc(ctx_src->ipad_ctx, &status);
    if (!ctx_dest->ipad_ctx || status != TCLIB_SUCCESS)
        return TCLIB_ERR_ALLOC_FAILED;

    // Allocate and clone outer hash context
    ctx_dest->opad_ctx = EVP_HashCloneCtxAlloc(ctx_src->opad_ctx, &status);
    if (!ctx_dest->opad_ctx || status != TCLIB_SUCCESS) {
        EVP_HashFree(ctx_dest->ipad_ctx);
        return TCLIB_ERR_ALLOC_FAILED;
    }

    // Copy simple fields
    SECURE_MEMCPY(ctx_dest->key, ctx_src->key, ctx_src->key_len);
    ctx_dest->key_len     = ctx_src->key_len;
    ctx_dest->out_len     = ctx_src->out_len;
    ctx_dest->isFinalized = ctx_src->isFinalized;
    ctx_dest->isHeapAlloc = 0; // pre-allocated

    return TCLIB_SUCCESS;
}

ll_HMAC_CTX *ll_HMAC_CloneCtxAlloc(const ll_HMAC_CTX *ctx_src, TCLIB_STATUS *status) {
    if (!ctx_src) {
        if (status) *status = TCLIB_ERR_NULL_PTR;
        return NULL;
    }

    // Allocate the destination context
    ll_HMAC_CTX *ctx_dest = CREATE_CTX(ll_HMAC_CTX);
    if (!ctx_dest) {
        if (status) *status = TCLIB_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Use the in-place clone function
    TCLIB_STATUS ret = ll_HMAC_CloneCtx(ctx_dest, ctx_src);
    if (ret != TCLIB_SUCCESS) {
        DESTROY_CTX(ctx_dest, sizeof(ll_HMAC_CTX));
        return NULL;
    }

    // Mark as heap-allocated
    ctx_dest->isHeapAlloc = 1;

    return ctx_dest;
}