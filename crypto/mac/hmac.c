#include "hmac.h"

// HMAC Rules / Steps (RFC 2104)
// Normalize the key

// Let B = block size of the hash (e.g., SHA256 → 64 bytes).

// If key_len > B → hash the key and use the digest as the new key.

// If key_len < B → pad the key with zeros to make it exactly B bytes.

// Call this padded key K'.

// Prepare the inner and outer pads

// ipad = 0x36 repeated B times

// opad = 0x5C repeated B times

// XOR the key with the pads

// K'_inner = K' XOR ipad

// K'_outer = K' XOR opad

// Compute the inner hash

// inner_hash = H(K'_inner || message)

// Concatenate the XORed key with the message

// Hash it using the underlying hash function

// Compute the final HMAC

// HMAC = H(K'_outer || inner_hash)

// Concatenate the XORed key for outer with the inner hash result

// Hash it again → this is the final HMAC

// Optional: Squeeze (for SHAKE / XOF)

// Only for extendable-output functions like SHAKE.

// After final, produce as many bytes as needed.

// typedef struct _ll_HMAC_CTX {
//     const EVP_MD *md;                         // Low-level hash descriptor
//     void *ipad_ctx;                           // Inner hash context
//     void *opad_ctx;                           // Outer hash context
//     uint8_t key[EVP_MAX_DEFAULT_BLOCK_SIZE];  // Pre-padded key (max block size)
//     size_t key_len;

//     isHeapAlloc;
// } ll_HMAC_CTX;

EVP_STATUS ll_HMAC_Init(ll_HMAC_CTX *ctx, const EVP_MD *md, const uint8_t *key, size_t key_len) {
    if (!ctx || !md || !key)
        return EVP_ERR_NULL_PTR;

    if (key_len == 0)
        return EVP_ERR_INVALID_LEN;

    if (EVP_IS_XOF(md->id))
        return EVP_ERR_UNSUPPORTED;

    if (md->block_size == 0 || md->block_size > EVP_MAX_DEFAULT_BLOCK_SIZE)
        return EVP_ERR_UNSUPPORTED;

    ctx->md = md;
    ctx->out_len = md->digest_size != 0 ? md->digest_size : md->default_out_len;

    // allocate low-level internal contexts
    ctx->ipad_ctx = SECURE_ALLOC(md->ctx_size);
    if (!ctx->ipad_ctx)
        return EVP_ERR_ALLOC_FAILED;

    ctx->opad_ctx = SECURE_ALLOC(md->ctx_size);
    if (!ctx->opad_ctx) {
        SECURE_FREE(ctx->ipad_ctx, md->ctx_size);
        return EVP_ERR_ALLOC_FAILED;
    }

    // // Use a local variable for the effective key length after normalization.
    // // This avoids clobbering the callers key_len or confusing logic.
    // size_t key_used_len = key_len;

    // normalize key
    if (key_len > md->block_size) {
        if (!md->hash_init_fn(ctx->ipad_ctx) ||
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

    // store both logical key length (useful later) and padded block size
    ctx->key_len = md->block_size;           // number of meaningful key bytes
    // ctx->key_block_size = md->block_size;  // block size used for padding / ipad/opad   
    

    // apply XOR pads
    uint8_t ipad[EVP_MAX_DEFAULT_BLOCK_SIZE], opad[EVP_MAX_DEFAULT_BLOCK_SIZE];
    for (size_t i = 0; i < md->block_size; i++) {
        ipad[i] = ctx->key[i] ^ 0x36;
        opad[i] = ctx->key[i] ^ 0x5c;
    }

    // init hash contexts and feed pads
    if (!md->hash_init_fn(ctx->ipad_ctx) ||
        !md->hash_init_fn(ctx->opad_ctx))
        goto cleanup;

    if (!md->hash_update_fn(ctx->ipad_ctx, ipad, md->block_size) ||
        !md->hash_update_fn(ctx->opad_ctx, opad, md->block_size))
        goto cleanup;

    SECURE_ZERO(ipad, md->block_size);
    SECURE_ZERO(opad, md->block_size);

    ctx->isHeapAlloc = 0;
    ctx->isFinalized = 0;
    return EVP_OK;

cleanup:
    if (ctx->ipad_ctx) {
        SECURE_ZERO(ctx->ipad_ctx, md->ctx_size);
        SECURE_FREE(ctx->ipad_ctx, md->ctx_size);
    }

    if (ctx->opad_ctx) {
        SECURE_ZERO(ctx->opad_ctx, md->ctx_size);
        SECURE_FREE(ctx->opad_ctx, md->ctx_size);
    }

    return EVP_ERR_CTX_CORRUPT;
}

ll_HMAC_CTX* ll_HMAC_InitAlloc(const EVP_MD *md, const uint8_t *key, size_t key_len, EVP_STATUS *status) {
    if (!md) {
        if (status) *status = EVP_ERR_NULL_PTR;
        return NULL;
    }

    ll_HMAC_CTX *ctx = CREATE_CTX(ll_HMAC_CTX);
    if (!ctx) {
        if (status) *status = EVP_ERR_ALLOC_FAILED;
        return NULL;
    }

    EVP_STATUS st = ll_HMAC_Init(ctx, md, key, key_len);
    if (st != EVP_OK) {
        DESTROY_CTX(ctx, ll_HMAC_CTX);
        if (status) *status = st;
        return NULL;
    }

    ctx->isHeapAlloc = 1;
    if (status) *status = EVP_OK;
    return ctx;
}

EVP_STATUS ll_HMAC_Update(ll_HMAC_CTX *ctx, const uint8_t *data, size_t data_len) {
    if (!ctx || !ctx->md || !ctx->ipad_ctx || !data)
        return EVP_ERR_NULL_PTR;

    if (data_len == 0)
        return EVP_ERR_INVALID_LEN;

    if (!ctx->md->hash_update_fn(ctx->ipad_ctx, data, data_len))
        return EVP_ERR_CTX_CORRUPT;

    return EVP_OK;
}

EVP_STATUS ll_HMAC_Final(ll_HMAC_CTX *ctx, uint8_t *digest, size_t digest_len) {
    if (!ctx || !ctx->md || !ctx->ipad_ctx || !ctx->opad_ctx)
        return EVP_ERR_NULL_PTR;

    size_t final_len = (digest_len != 0) ? digest_len : ctx->out_len;
    if (final_len > ctx->out_len) final_len = ctx->out_len; // clamp

    // compute inner hash
    uint8_t inner_hash[EVP_MAX_DEFAULT_DIGEST_SIZE];
    if (!ctx->md->hash_final_fn(ctx->ipad_ctx, inner_hash, ctx->md->digest_size))
        return EVP_ERR_CTX_CORRUPT;

    // feed inner hash into opad context
    if (!ctx->md->hash_update_fn(ctx->opad_ctx, inner_hash, ctx->md->digest_size))
        return EVP_ERR_CTX_CORRUPT;

    // compute final HMAC
    if (!ctx->md->hash_final_fn(ctx->opad_ctx, digest, final_len))
        return EVP_ERR_CTX_CORRUPT;

    SECURE_ZERO(inner_hash, sizeof(inner_hash));
    ctx->isFinalized = 1;
    return EVP_OK;
}

EVP_STATUS ll_HMAC_Free(ll_HMAC_CTX *ctx) {
    if (!ctx) return EVP_ERR_NULL_PTR;

    if (ctx->ipad_ctx && ctx->md) {
    SECURE_ZERO(ctx->ipad_ctx, ctx->md->ctx_size);
    SECURE_FREE(ctx->ipad_ctx, ctx->md->ctx_size);
    }

    if (ctx->opad_ctx && ctx->md) {
        SECURE_ZERO(ctx->opad_ctx, ctx->md->ctx_size);
        SECURE_FREE(ctx->opad_ctx, ctx->md->ctx_size);
    }

    if (ctx->isHeapAlloc) DESTROY_CTX(ctx, ll_HMAC_CTX);

    return EVP_OK;
}

EVP_STATUS ll_HMAC_Reset(ll_HMAC_CTX *ctx) {
    if (!ctx || !ctx->md || !ctx->ipad_ctx || !ctx->opad_ctx) return EVP_ERR_NULL_PTR;

    // re-apply XOR pads
    uint8_t ipad[EVP_MAX_DEFAULT_BLOCK_SIZE], opad[EVP_MAX_DEFAULT_BLOCK_SIZE];
    for (size_t i = 0; i < ctx->md->block_size; i++) {
        ipad[i] = ctx->key[i] ^ 0x36;
        opad[i] = ctx->key[i] ^ 0x5c;
    }

    // reset low-level hash contexts
    if (!ctx->md->hash_init_fn(ctx->ipad_ctx) ||
        !ctx->md->hash_init_fn(ctx->opad_ctx)) return EVP_ERR_BAD_STATE;

    if (!ctx->md->hash_update_fn(ctx->ipad_ctx, ipad, ctx->md->block_size) ||
        !ctx->md->hash_update_fn(ctx->opad_ctx, opad, ctx->md->block_size)) return EVP_ERR_BAD_STATE;

    SECURE_ZERO(ipad, ctx->md->block_size);
    SECURE_ZERO(opad, ctx->md->block_size);

    ctx->out_len = ctx->md->digest_size != 0 ? ctx->md->digest_size : ctx->md->default_out_len;
    ctx->isFinalized = 0;
    return EVP_OK;
}