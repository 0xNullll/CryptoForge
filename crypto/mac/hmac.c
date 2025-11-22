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

    // assign algorithm descriptor
    ctx->md = md;

    // allocate low-level internal contexts first
    ctx->ipad_ctx = SECURE_ALLOC(md->ctx_size);
    if (!ctx->ipad_ctx) return EVP_ERR_ALLOC_FAILED;

    ctx->opad_ctx = SECURE_ALLOC(md->ctx_size);
    if (!ctx->opad_ctx) {
        SECURE_FREE(ctx->ipad_ctx, md->ctx_size);
        return EVP_ERR_ALLOC_FAILED;
    }

    // normalize key into ctx->key
    if (key_len > ctx->md->block_size) {
        // hash long key using existing ipad_ctx temporarily
        if (!ctx->md->hash_init_fn(ctx->ipad_ctx) ||
            !ctx->md->hash_update_fn(ctx->ipad_ctx, key, key_len) ||
            !ctx->md->hash_final_fn(ctx->ipad_ctx, ctx->key, ctx->md->digest_size)) {
            return EVP_ERR_CTX_CORRUPT;
        }

        if (ctx->md->hash_squeeze_fn) {
            if (!ctx->md->hash_squeeze_fn(ctx->ipad_ctx, ctx->key, ctx->md->digest_size)) {
                return EVP_ERR_CTX_CORRUPT;
            }
        }

        key_len = ctx->md->digest_size;
    } else {
        // copy short key
        SECURE_MEMCPY(ctx->key, key, key_len);
    }

    // zero pad to block size
    if (key_len < md->block_size) {
        SECURE_MEMSET(ctx->key + key_len, 0, md->block_size - key_len);
    }
    ctx->key_len = md->block_size;

    // prepare XORed pads
    uint8_t ipad[EVP_MAX_DEFAULT_BLOCK_SIZE];
    uint8_t opad[EVP_MAX_DEFAULT_BLOCK_SIZE];
    for (size_t i = 0; i < md->block_size; i++) {
        ipad[i] = ctx->key[i] ^ 0x36;
        opad[i] = ctx->key[i] ^ 0x5c;
    }

    // initialize low-level hash contexts
    if (!ctx->md->hash_init_fn(ctx->ipad_ctx) ||
        !ctx->md->hash_init_fn(ctx->opad_ctx)) {
        goto cleanup;
    }

    // feed XORed pads
    if (!ctx->md->hash_update_fn(ctx->ipad_ctx, ipad, md->block_size) ||
        !ctx->md->hash_update_fn(ctx->opad_ctx, opad, md->block_size)) {
        goto cleanup;
    }

    // clear temporary pads from stack
    SECURE_ZERO(ipad, md->block_size);
    SECURE_ZERO(opad, md->block_size);

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
    if (!ctx || !ctx->md || !ctx->ipad_ctx || !ctx->opad_ctx ) 
        return EVP_ERR_NULL_PTR;
        



    return EVP_OK;    
}