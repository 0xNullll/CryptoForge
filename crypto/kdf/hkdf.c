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

    size_t final_len = 0;

#ifdef HKDF_FALLBACK_DEFAULT_LEN
    final_len = (ikm_len != 0) ? ikm_len : ctx->md->default_out_len;
#else
    if (ikm_len == 0)
        return CF_ERR_INVALID_LEN;
    final_len = ikm_len;
#endif

    // Safety cap: cannot exceed hash output
    if (final_len > ctx->md->default_out_len)
        final_len = ctx->md->default_out_len;

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
    ctx->prk = (uint8_t *)SECURE_ALLOC(final_len);
    if (!ctx->prk) {
        ll_HMAC_Free(hmac_ctx);
        SECURE_FREE(hmac_ctx, sizeof(ll_HMAC_CTX));
        return CF_ERR_ALLOC_FAILED;
    }

    st = ll_HMAC_Final(hmac_ctx, ctx->prk, final_len);
    ll_HMAC_Free(hmac_ctx);                     // clean internal buffers
    SECURE_FREE(hmac_ctx, sizeof(ll_HMAC_CTX)); // free the struct itself
    if (st != CF_SUCCESS) {
        SECURE_FREE((void *)ctx->prk, final_len);
        ctx->prk = NULL;
        return st;
    }

    ctx->prk_len = final_len;
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
    const size_t max_okm =  LL_HKDF_MAX_OKM(hash_len); // RFC 5869 limit
    size_t final_len = 0;

#ifdef HKDF_FALLBACK_DEFAULT_LEN
    final_len = (okm_len != 0) ? okm_len : hash_len;
#else
    if (okm_len == 0)
        return CF_ERR_INVALID_LEN;
    final_len = okm_len;
#endif

    if (final_len > max_okm)
        return CF_ERR_LIMIT_EXCEEDED;

    // Replace info if new_info is provided
    if (new_info) {
        if (ctx->info) {
            SECURE_FREE(ctx->info, ctx->info_len);
            ctx->info = NULL;
        }
        ctx->info = (uint8_t *)SECURE_ALLOC(new_info_len);
        if (!ctx->info)
            return CF_ERR_ALLOC_FAILED;
        SECURE_MEMCPY((void *)ctx->info, new_info, new_info_len);
        ctx->info_len = new_info_len;
    }

    uint8_t block[EVP_MAX_DEFAULT_BLOCK_SIZE];
    size_t generated = 0;
    size_t prev_block_len = 0;

    ll_HMAC_CTX *hmac_ctx = (ll_HMAC_CTX *)SECURE_ALLOC(sizeof(ll_HMAC_CTX));
    if (!hmac_ctx)
        return CF_ERR_ALLOC_FAILED;

    CF_STATUS st;

    // Loop to generate blocks until OKM is fully filled
    while (generated < final_len) {
        if (ctx->counter >= 255) {
            ll_HMAC_Free(hmac_ctx);
            SECURE_FREE(hmac_ctx, sizeof(ll_HMAC_CTX));
            return CF_ERR_LIMIT_EXCEEDED;
        }

        ctx->counter++; // block index (starts at 1)

        // Initialize HMAC with PRK
        st = ll_HMAC_Init(hmac_ctx, ctx->md, ctx->prk, ctx->prk_len);
        if (st != CF_SUCCESS)
            goto cleanup;

        // Feed previous block (empty for first), info, and counter
        if (prev_block_len)
            st = ll_HMAC_Update(hmac_ctx, ctx->prev_block, prev_block_len);
        if (st == CF_SUCCESS && ctx->info && ctx->info_len)
            st = ll_HMAC_Update(hmac_ctx, ctx->info, ctx->info_len);
        if (st == CF_SUCCESS)
            st = ll_HMAC_Update(hmac_ctx, &ctx->counter, 1);

        if (st != CF_SUCCESS)
            goto cleanup;

        // Finalize HMAC block
        st = ll_HMAC_Final(hmac_ctx, block, hash_len);
        if (st != CF_SUCCESS)
            goto cleanup;

        // Copy appropriate number of bytes to OKM
        size_t to_copy = (final_len - generated) > hash_len ? hash_len : (final_len - generated);
        SECURE_MEMCPY(okm + generated, block, to_copy);
        generated += to_copy;

        // Save current block for next iteration
        SECURE_MEMCPY(ctx->prev_block, block, hash_len);
        prev_block_len = hash_len;
    }

    ll_HMAC_Free(hmac_ctx);
    SECURE_FREE(hmac_ctx, sizeof(ll_HMAC_CTX));
    return CF_SUCCESS;

cleanup:
    ll_HMAC_Free(hmac_ctx);
    SECURE_FREE(hmac_ctx, sizeof(ll_HMAC_CTX));
    return st;
}
