/*
 * CryptoForge - cf_mac.c / High-level MAC context and utility implementation
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against WyChaProof test vectors. No hardware optimizations. Use with caution.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#include "../../include/cf_api/cf_mac.h"

//
// Wrappers for all MACs
//

// HMAC
static CF_STATUS hmac_init_wrapper(CF_MAC_CTX *ctx, const CF_MAC_OPTS *opts) {
    UNUSED(opts);
    return ll_HMAC_Init((ll_HMAC_CTX *)ctx->mac_ctx, ctx->md, ctx->key, ctx->key_len);
}
static CF_STATUS hmac_update_wrapper(CF_MAC_CTX *ctx, const uint8_t *data, size_t data_len) {
    return ll_HMAC_Update((ll_HMAC_CTX *)ctx->mac_ctx, data, data_len);
}
static CF_STATUS hmac_final_wrapper(CF_MAC_CTX *ctx, uint8_t *tag, size_t tag_len) {
    return ll_HMAC_Final((ll_HMAC_CTX *)ctx->mac_ctx, tag, tag_len);
}
static CF_STATUS hmac_reset_wrapper(CF_MAC_CTX *ctx) {
    return ll_HMAC_Reset((ll_HMAC_CTX *)ctx->mac_ctx);
}
static CF_STATUS hmac_verify_wrapper(CF_MAC_CTX *ctx,
                                     const uint8_t *data, size_t data_len,
                                     const uint8_t *expected_tag, size_t expected_tag_len,
                                     const struct _CF_MAC_OPTS *opts) {
    UNUSED(opts);
    return ll_HMAC_Verify((const CF_MD *)ctx->md, ctx->key, ctx->key_len, 
                          data, data_len, expected_tag, expected_tag_len);
}
static CF_STATUS hmac_clone_ctx_wrapper(CF_MAC_CTX *dest_ctx, const CF_MAC_CTX *src_ctx) {
    return ll_HMAC_CloneCtx((ll_HMAC_CTX *)dest_ctx->mac_ctx, (const ll_HMAC_CTX *)src_ctx->mac_ctx);
}

// KMAC
static CF_STATUS kmac_init_wrapper(CF_MAC_CTX *ctx, const CF_MAC_OPTS *opts) {
    return ll_KMAC_Init((ll_KMAC_CTX *)ctx->mac_ctx, ctx->key, ctx->key_len, opts->custom, opts->custom_len, ctx->subflags);
}

static CF_STATUS kmac_update_wrapper(CF_MAC_CTX *ctx, const uint8_t *data, size_t data_len) {
    return ll_KMAC_Update((ll_KMAC_CTX *)ctx->mac_ctx, data, data_len);
}
static CF_STATUS kmac_final_wrapper(CF_MAC_CTX *ctx, uint8_t *tag, size_t tag_len) {
    return ll_KMAC_Final((ll_KMAC_CTX *)ctx->mac_ctx, tag, tag_len);
}
static CF_STATUS kmac_reset_wrapper(CF_MAC_CTX *ctx) {
    return ll_KMAC_Reset((ll_KMAC_CTX *)ctx->mac_ctx);
}
static CF_STATUS kmac_verify_wrapper(CF_MAC_CTX *ctx,
                                     const uint8_t *data, size_t data_len,
                                     const uint8_t *expected_tag, size_t expected_tag_len,
                                     const struct _CF_MAC_OPTS *opts) {
    return ll_KMAC_Verify(ctx->key, ctx->key_len, data, data_len,
                          opts->custom, opts->custom_len, expected_tag, expected_tag_len,
                          ctx->subflags);
}
static CF_STATUS kmac_clone_ctx_wrapper(CF_MAC_CTX *dest_ctx, const CF_MAC_CTX *src_ctx) {
    return ll_KMAC_CloneCtx((ll_KMAC_CTX *)dest_ctx->mac_ctx, (const ll_KMAC_CTX *)src_ctx->mac_ctx);
}

// CMAC
static CF_STATUS cmac_init_wrapper(CF_MAC_CTX *ctx, const CF_MAC_OPTS *opts) {
    UNUSED(opts);
    return ll_CMAC_Init((ll_CMAC_CTX *)ctx->mac_ctx, (const ll_AES_KEY *)ctx->cipher_key);
}
static CF_STATUS cmac_update_wrapper(CF_MAC_CTX *ctx, const uint8_t *data, size_t data_len) {
    return ll_CMAC_Update((ll_CMAC_CTX *)ctx->mac_ctx, data, data_len);
}
static CF_STATUS cmac_final_wrapper(CF_MAC_CTX *ctx, uint8_t *tag, size_t tag_len) {
    return ll_CMAC_Final((ll_CMAC_CTX *)ctx->mac_ctx, tag, tag_len);
}
static CF_STATUS cmac_reset_wrapper(CF_MAC_CTX *ctx) {
    return ll_CMAC_Reset((ll_CMAC_CTX *)ctx->mac_ctx);
}
static CF_STATUS cmac_verify_wrapper(CF_MAC_CTX *ctx,
                                     const uint8_t *data, size_t data_len,
                                     const uint8_t *expected_tag, size_t expected_tag_len,
                                     const struct _CF_MAC_OPTS *opts) {
    UNUSED(opts);
    return ll_CMAC_Verify((const ll_AES_KEY *)ctx->cipher_key, data, data_len,
                          expected_tag, expected_tag_len);
}
static CF_STATUS cmac_clone_ctx_wrapper(CF_MAC_CTX *dest_ctx, const CF_MAC_CTX *src_ctx) {
    return ll_CMAC_CloneCtx((ll_CMAC_CTX *)dest_ctx->mac_ctx, (const ll_CMAC_CTX *)src_ctx->mac_ctx);
}

// GMAC
static CF_STATUS gmac_init_wrapper(CF_MAC_CTX *ctx, const CF_MAC_OPTS *opts) {
    return ll_GMAC_Init((ll_GMAC_CTX *)ctx->mac_ctx, (const ll_AES_KEY *)ctx->cipher_key, opts->iv, opts->iv_len);
}
static CF_STATUS gmac_update_wrapper(CF_MAC_CTX *ctx, const uint8_t *data, size_t data_len) {
    return ll_GMAC_Update((ll_GMAC_CTX *)ctx->mac_ctx, data, data_len);
}
static CF_STATUS gmac_final_wrapper(CF_MAC_CTX *ctx, uint8_t *tag, size_t tag_len) {
    return ll_GMAC_Final((ll_GMAC_CTX *)ctx->mac_ctx, tag, tag_len);
}
static CF_STATUS gmac_reset_wrapper(CF_MAC_CTX *ctx) {
    return ll_GMAC_Reset((ll_GMAC_CTX *)ctx->mac_ctx);
}
static CF_STATUS gmac_verify_wrapper(CF_MAC_CTX *ctx,
                                     const uint8_t *data, size_t data_len,
                                     const uint8_t *expected_tag, size_t expected_tag_len,
                                     const struct _CF_MAC_OPTS *opts) {
    return ll_GMAC_Verify((const ll_AES_KEY *)ctx->cipher_key, opts->iv, opts->iv_len,
                           data, data_len, expected_tag, expected_tag_len);
}
static CF_STATUS gmac_clone_ctx_wrapper(CF_MAC_CTX *dest_ctx, const CF_MAC_CTX *src_ctx) {
    return ll_GMAC_CloneCtx((ll_GMAC_CTX *)dest_ctx->mac_ctx, (const ll_GMAC_CTX *)src_ctx->mac_ctx);
}

// poly1305
static CF_STATUS poly1305_init_wrapper(CF_MAC_CTX *ctx, const CF_MAC_OPTS *opts) {
    UNUSED(opts);
    return ll_POLY1305_Init((ll_POLY1305_CTX *)ctx->mac_ctx, ctx->key);
}
static CF_STATUS poly1305_update_wrapper(CF_MAC_CTX *ctx, const uint8_t *data, size_t data_len) {
    return ll_POLY1305_Update((ll_POLY1305_CTX *)ctx->mac_ctx, data, data_len);
}
static CF_STATUS poly1305_final_wrapper(CF_MAC_CTX *ctx, uint8_t *tag, size_t tag_len) {
    UNUSED(tag_len);
    return ll_POLY1305_Final((ll_POLY1305_CTX *)ctx->mac_ctx, tag);
}
static CF_STATUS poly1305_reset_wrapper(CF_MAC_CTX *ctx) {
    return ll_POLY1305_Reset((ll_POLY1305_CTX *)ctx->mac_ctx);
}
static CF_STATUS poly1305_verify_wrapper(CF_MAC_CTX *ctx,
                                     const uint8_t *data, size_t data_len,
                                     const uint8_t *expected_tag, size_t expected_tag_len,
                                     const struct _CF_MAC_OPTS *opts) {
    UNUSED(opts);
    UNUSED(expected_tag_len);
    return ll_POLY1305_Verify(ctx->key, data, data_len, expected_tag);
}
static CF_STATUS poly1305_clone_ctx_wrapper(CF_MAC_CTX *dest_ctx, const CF_MAC_CTX *src_ctx) {
    return ll_POLY1305_CloneCtx((ll_POLY1305_CTX *)dest_ctx->mac_ctx, (const ll_POLY1305_CTX *)src_ctx->mac_ctx);
}

// --- CF_MAC Return Functions ---

//
// HMAC
//
static const CF_MAC *CF_get_hmac(void) {
    static CF_MAC mac = {
        .id = CF_HMAC,
        .ctx_size = sizeof(ll_HMAC_CTX),
        .key_ctx_size = 0,
        .default_tag_len = 0,
        .mac_init_fn = hmac_init_wrapper,
        .mac_update_fn = hmac_update_wrapper,
        .mac_final_fn = hmac_final_wrapper,
        .mac_reset_fn = hmac_reset_wrapper,
        .mac_verify_fn = hmac_verify_wrapper,
        .mac_clone_ctx_fn = hmac_clone_ctx_wrapper
    };
    return &mac;
}

//
// KMAC
//
static const CF_MAC *CF_get_kmac(void) {
    static CF_MAC mac = {
        .id = CF_KMAC_STD,
        .ctx_size = sizeof(ll_KMAC_CTX),
        .key_ctx_size = 0,
        .default_tag_len = 0,
        .mac_init_fn = kmac_init_wrapper,
        .mac_update_fn = kmac_update_wrapper,
        .mac_final_fn = kmac_final_wrapper,
        .mac_reset_fn = kmac_reset_wrapper,
        .mac_verify_fn = kmac_verify_wrapper,
        .mac_clone_ctx_fn = kmac_clone_ctx_wrapper
    };
    return &mac;
}

//
// CMAC
//
static const CF_MAC *CF_get_cmac(void) {
    static CF_MAC mac = {
        .id = CF_CMAC,
        .ctx_size = sizeof(ll_CMAC_CTX),
        .key_ctx_size = sizeof(ll_AES_KEY),
        .default_tag_len = AES_BLOCK_SIZE,
        .mac_init_fn = cmac_init_wrapper,
        .mac_update_fn = cmac_update_wrapper,
        .mac_final_fn = cmac_final_wrapper,
        .mac_reset_fn = cmac_reset_wrapper,
        .mac_verify_fn = cmac_verify_wrapper,
        .mac_clone_ctx_fn = cmac_clone_ctx_wrapper
    };
    return &mac;
}

//
// GMAC
//
static const CF_MAC *CF_get_gmac(void) {
    static CF_MAC mac = {
        .id = CF_GMAC,
        .ctx_size = sizeof(ll_GMAC_CTX),
        .key_ctx_size = sizeof(ll_AES_KEY),
        .default_tag_len = AES_BLOCK_SIZE,
        .mac_init_fn = gmac_init_wrapper,
        .mac_update_fn = gmac_update_wrapper,
        .mac_final_fn = gmac_final_wrapper,
        .mac_reset_fn = gmac_reset_wrapper,
        .mac_verify_fn = gmac_verify_wrapper,
        .mac_clone_ctx_fn = gmac_clone_ctx_wrapper
    };
    return &mac;
}

//
// poly1305
//
static const CF_MAC *CF_get_poly1305(void) {
    static CF_MAC mac = {
        .id = CF_POLY1305,
        .ctx_size = sizeof(ll_POLY1305_CTX),
        .key_ctx_size = 0,
        .default_tag_len = LL_POLY1305_TAG_LEN,
        .mac_init_fn = poly1305_init_wrapper,
        .mac_update_fn = poly1305_update_wrapper,
        .mac_final_fn = poly1305_final_wrapper,
        .mac_reset_fn = poly1305_reset_wrapper,
        .mac_verify_fn = poly1305_verify_wrapper,
        .mac_clone_ctx_fn = poly1305_clone_ctx_wrapper
    };
    return &mac;
}

// Table of all supported MACs
static const CF_ALGO_ENTRY cf_mac_table[] = {
    { CF_HMAC,      (const void* (*)(void))CF_get_hmac     },
    { CF_KMAC_STD,  (const void* (*)(void))CF_get_kmac     },
    { CF_CMAC,      (const void* (*)(void))CF_get_cmac     },
    { CF_GMAC,      (const void* (*)(void))CF_get_gmac     },
    { CF_POLY1305,  (const void* (*)(void))CF_get_poly1305 }
};

const CF_MAC *CF_MAC_GetByFlag(uint32_t algo_flag) {
    if (!CF_IS_MAC(algo_flag)) 
        return NULL;

    size_t table_len = sizeof(cf_mac_table) / sizeof(cf_mac_table[0]);
    for (size_t i = 0; i < table_len; i++) {
        if (cf_mac_table[i].flag == algo_flag) {
            return (const CF_MAC*)cf_mac_table[i].getter_fn();
        }
    }
    return NULL;
}

CF_STATUS CF_MAC_Init(CF_MAC_CTX *ctx, const CF_MAC *mac, const CF_MAC_OPTS *opts,
                      const uint8_t *key, size_t key_len, uint32_t subflags) {
    if (!ctx || !mac || !key)
        return CF_ERR_NULL_PTR;

    if (opts && opts->magic != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    if (ctx->isHeapAlloc != 0 && ctx->isHeapAlloc != 1)
        return CF_ERR_CTX_UNINITIALIZED;

    // Fresh cleanup
    CF_MAC_Reset(ctx);

    ctx->mac      = mac;
    ctx->opts     = opts;
    ctx->key      = key;
    ctx->key_len  = key_len;
    ctx->subflags = subflags;

    if (CF_MAC_IS_HMAC(ctx->mac->id)) {
        // HMAC: requires a hash subflag, cannot have KMAC bits
        if ((subflags & CF_MAC_KMAC_MASK) != 0)
            return CF_ERR_INVALID_PARAM;

        if ((subflags & CF_HASH_MASK) == 0)
            return CF_ERR_INVALID_PARAM; // must specify hash

        if (CF_IS_XOF(subflags))
            return CF_ERR_UNSUPPORTED;

        ctx->md = CF_MD_GetByFlag(subflags);
        if (!ctx->md)
            return CF_ERR_UNSUPPORTED;

        ctx->tag_len = ctx->md->default_out_len;

    } else if (CF_MAC_IS_KMAC_STD(ctx->mac->id)) {
        // KMAC: must have KMAC type, cannot have hash flags
        if ((subflags & CF_MAC_KMAC_MASK) == 0)
            return CF_ERR_INVALID_PARAM;

        if ((subflags & CF_HASH_MASK) != 0)
            return CF_ERR_INVALID_PARAM;

    } else if (CF_MAC_IS_CMAC(ctx->mac->id) || CF_MAC_IS_GMAC(ctx->mac->id)) {
        // AES MACs: CMAC / GMAC
        if (!CF_IS_AES_KEY_VALID(key_len))
            return CF_ERR_CIPHER_INVALID_KEY_LEN;

        ctx->cipher_key_len = key_len;
        ctx->tag_len = ctx->mac->default_tag_len;

        ctx->cipher_key = (void *)SECURE_ALLOC(ctx->mac->key_ctx_size);
        if (!ctx->cipher_key)
            return CF_ERR_ALLOC_FAILED;

        if (!ll_AES_SetEncryptKey((ll_AES_KEY *)ctx->cipher_key, key, ctx->cipher_key_len)) {
            SECURE_FREE(ctx->cipher_key, ctx->mac->key_ctx_size);
            return CF_ERR_CIPHER_KEY_SETUP;
        }

    } else if (CF_MAC_IS_POLY1305(ctx->mac->id)) {
        if (key_len != LL_POLY1305_KEY_LEN)
            return CF_ERR_MAC_INVALID_KEY_LEN;

        ctx->tag_len = ctx->mac->default_tag_len;

    } else {
        return CF_ERR_INVALID_PARAM;
    }

    // Reject invalid MAC context size
    if (ctx->mac->ctx_size == 0) 
        return CF_ERR_CTX_CORRUPT;

    ctx->mac_ctx = (void *)SECURE_ALLOC(ctx->mac->ctx_size);
    if (!ctx->mac_ctx) {
        if (ctx->cipher_key)
            SECURE_FREE(ctx->cipher_key, ctx->mac->key_ctx_size);
        return CF_ERR_ALLOC_FAILED;
    }

    // Initialize context
    CF_STATUS st = ctx->mac->mac_init_fn(ctx, ctx->opts);
    if (st != CF_SUCCESS) {
        if (ctx->mac_ctx)
            SECURE_FREE(ctx->mac_ctx, ctx->mac->ctx_size);
        if (ctx->cipher_key)
            SECURE_FREE(ctx->cipher_key, ctx->mac->key_ctx_size);
        return st;
    }

    // Integrity check: bind the MAC pointer to a per-context "magic" value
    // to detect accidental corruption or misuse of the context.
    // Note: this does NOT prevent a determined attacker from tampering with memory.
    ctx->magic = CF_CTX_MAGIC ^ (uintptr_t)ctx->mac;

    return CF_SUCCESS;
}

CF_MAC_CTX* CF_MAC_InitAlloc(const CF_MAC *mac, const CF_MAC_OPTS *opts,
                             const uint8_t *key, size_t key_len, uint32_t subflags,
                             CF_STATUS *status) {
    if (!mac || !key) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    CF_MAC_CTX *ctx = (CF_MAC_CTX *)SECURE_ALLOC(sizeof(CF_MAC_CTX));
    if (!ctx) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    CF_STATUS st = CF_MAC_Init(ctx, mac, opts, key, key_len, subflags);
    if (st != CF_SUCCESS) {
        SECURE_FREE(ctx, sizeof(CF_MAC_CTX));
        if (status) *status = st;
        return NULL;
    }

    ctx->isHeapAlloc = 1;
    if (status) *status = CF_SUCCESS;
    return ctx;
}

CF_STATUS CF_MAC_Update(CF_MAC_CTX *ctx, const uint8_t *data, size_t data_len) {
    if (!ctx || !data)
        return CF_ERR_NULL_PTR;

    if (!ctx->mac_ctx)
        return CF_ERR_CTX_UNINITIALIZED;

    // Verify that the MAC pointer hasn’t been tampered with by checking it against the bound magic value.
    if ((ctx->magic ^ (uintptr_t)ctx->mac) != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    if (ctx->isFinalized)
        return CF_ERR_MAC_FINALIZED;

    return ctx->mac->mac_update_fn(ctx, data, data_len);
}

CF_STATUS CF_MAC_Final(CF_MAC_CTX *ctx, uint8_t *tag, size_t tag_len) {
    if (!ctx || !tag)
        return CF_ERR_NULL_PTR;

    if ((!ctx->md && CF_MAC_IS_HMAC(ctx->mac->id)) || !ctx->mac_ctx)
        return CF_ERR_CTX_UNINITIALIZED;

    // Verify that the MAC pointer hasn’t been tampered with by checking it against the bound magic value.
    if ((ctx->magic ^ (uintptr_t)ctx->mac) != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    if (tag_len == 0)
        return CF_ERR_INVALID_LEN;

    if (ctx->isFinalized) {
        if (!CF_MAC_IS_KMAC_STD(ctx->mac->id))
            return CF_ERR_HASH_FINALIZED;
        
        ctx->tag_len = tag_len;
    }
    
    if (CF_MAC_IS_HMAC(ctx->mac->id)) {
        if (ctx->md->default_out_len == 0)
            return CF_ERR_MAC_BAD_TAG_LEN;
    }

    else if (CF_MAC_IS_CMAC(ctx->mac->id)) {
        if (tag_len < 4 || tag_len > AES_BLOCK_SIZE)
            return CF_ERR_MAC_BAD_TAG_LEN;
    }

    else if (CF_MAC_IS_GMAC(ctx->mac->id)) {
        if (!IS_VALID_GCM_TAG_SIZE(tag_len))
                return CF_ERR_MAC_BAD_TAG_LEN;
    }

    else if (CF_MAC_IS_POLY1305(ctx->mac->id)) {
        if (tag_len != LL_POLY1305_TAG_LEN)
                return CF_ERR_MAC_BAD_TAG_LEN;
    }

    CF_STATUS st = CF_SUCCESS;
    size_t out_len = ctx->tag_len != 0 ? ctx->tag_len : tag_len;
    st = ctx->mac->mac_final_fn(ctx, tag, out_len);
    if (st != CF_SUCCESS)
        return st;

    ctx->isFinalized = 1;

    return CF_SUCCESS;
}

CF_STATUS CF_MAC_Reset(CF_MAC_CTX *ctx) {
    if (!ctx)
        return CF_ERR_NULL_PTR;

    if (!ctx->mac)
        return CF_ERR_CTX_UNINITIALIZED;

    if (!CF_IS_MAC(ctx->mac->id))
        return CF_ERR_UNSUPPORTED;

    CF_STATUS st = CF_SUCCESS;

    if (ctx->cipher_key) {
        if (ctx->mac->key_ctx_size == 0)
            return CF_ERR_CTX_CORRUPT;
        SECURE_FREE(ctx->cipher_key, ctx->mac->key_ctx_size);
    }

    if (ctx->mac_ctx) {
        st = ctx->mac->mac_reset_fn(ctx);  // pass full context
        if (st != CF_SUCCESS)
            return st;
        SECURE_FREE(ctx->mac_ctx, ctx->mac->ctx_size);
    }

    ctx->md = NULL;
    ctx->mac = NULL;
    ctx->cipher_key_len = 0;
    ctx->key = NULL;
    ctx->key_len = 0;
    ctx->tag_len = 0;
    ctx->subflags = 0;
    ctx->isFinalized = 0;

    return st;
}

CF_STATUS CF_MAC_Free(CF_MAC_CTX **p_ctx) {
    if (!p_ctx || !*p_ctx)
        return CF_ERR_NULL_PTR;

    CF_MAC_CTX *ctx = *p_ctx;

    CF_MAC_Reset(ctx);

    if (ctx->isHeapAlloc) {
        SECURE_ZERO(ctx, sizeof(CF_MAC_CTX));
    }

    return CF_SUCCESS;
}

CF_STATUS CF_MAC_Verify(const CF_MAC *mac,
                        const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        const uint8_t *expected_mac, size_t expected_mac_len,
                        const CF_MAC_OPTS *opts, uint32_t subflags) {
    if (!mac || !key || !data || !expected_mac)
        return CF_ERR_NULL_PTR;

    CF_STATUS st = CF_SUCCESS;
    CF_MAC_CTX ctx = {0};

    // Initialize context using standard MAC init
    st = CF_MAC_Init(&ctx, mac, opts, key, key_len, subflags);
    if (st != CF_SUCCESS || (ctx.magic ^ (uintptr_t)ctx.mac) != CF_CTX_MAGIC)
        return st;

    st = mac->mac_verify_fn(&ctx, data, data_len, expected_mac, expected_mac_len, opts);

    // Always securely clear context
    CF_MAC_Reset(&ctx);

    return st;
}

CF_STATUS CF_MAC_Compute(const CF_MAC *mac,
                         const uint8_t *key, size_t key_len,
                         const uint8_t *data, size_t data_len,
                         uint8_t *tag, size_t tag_len,
                         const CF_MAC_OPTS *opts, uint32_t subflags) {
    if (!mac || !key || !data || !tag)
        return CF_ERR_NULL_PTR;

    CF_MAC_CTX ctx = {0};
    CF_STATUS st = CF_SUCCESS;

    st = CF_MAC_Init(&ctx, mac, opts, key, key_len, subflags);
    if (st != CF_SUCCESS || (ctx.magic ^ (uintptr_t)ctx.mac) != CF_CTX_MAGIC)
        goto cleanup;

    st = CF_MAC_Update(&ctx, data, data_len);
    if (st != CF_SUCCESS || (ctx.magic ^ (uintptr_t)ctx.mac) != CF_CTX_MAGIC)
        goto cleanup;

    st = CF_MAC_Final(&ctx, tag, tag_len);

cleanup:
    CF_MAC_Reset(&ctx);
    return st;
}

const char* CF_MAC_GetName(const CF_MAC *ctx) {
    if (!ctx) return NULL;

    switch (ctx->id) {
    case CF_HMAC:     return "HMAC";
    case CF_KMAC_STD: return "KMAC";
    case CF_CMAC:     return "CMAC";
    case CF_GMAC:     return "GMAC";
    case CF_POLY1305: return "POLY-1305";
    default:          return NULL;
    }
}

const char* CF_MAC_GetFullName(const CF_MAC_CTX *ctx) {
    if (!ctx || !ctx->mac) return NULL;

    switch (ctx->mac->id) {
    case CF_HMAC:
        switch (ctx->subflags) {
        case CF_SHA1:       return "HMAC-SHA-1";
        case CF_SHA224:     return "HMAC-SHA-224";
        case CF_SHA256:     return "HMAC-SHA-256";
        case CF_SHA384:     return "HMAC-SHA-384";
        case CF_SHA512:     return "HMAC-SHA-512";
        case CF_SHA512_224: return "HMAC-SHA-512/224";
        case CF_SHA512_256: return "HMAC-SHA-512/256";
        case CF_SHA3_224:   return "HMAC-SHA-3/224";
        case CF_SHA3_256:   return "HMAC-SHA-3/256";
        case CF_SHA3_384:   return "HMAC-SHA-3/384";
        case CF_SHA3_512:   return "HMAC-SHA-3/512";
        default:            return "HMAC-UNKNOWN";
        }

    case CF_KMAC_STD:
        switch (ctx->subflags) {
        case CF_KMAC128:      return "KMAC-128";
        case CF_KMAC256:      return "KMAC-256";
        case CF_KMAC_XOF128:  return "KMAC-XOF-128";
        case CF_KMAC_XOF256:  return "KMAC-XOF-256";
        default:              return "KMAC-UNKNOWN";
        }

    case CF_CMAC:
        switch (ctx->key_len) {
        case AES_128_KEY_SIZE: return "CMAC-AES-128";
        case AES_192_KEY_SIZE: return "CMAC-AES-192";
        case AES_256_KEY_SIZE: return "CMAC-AES-256";
        default:               return "CMAC-UNKNOWN";
        }

    case CF_GMAC:
        switch (ctx->key_len) {
        case AES_128_KEY_SIZE: return "GMAC-AES-128";
        case AES_192_KEY_SIZE: return "GMAC-AES-192";
        case AES_256_KEY_SIZE: return "GMAC-AES-256";
        default:               return "GMAC-UNKNOWN";
        }

    case CF_POLY1305:          return "POLY-1305";

    default:
        return "UNKNOWN-MAC";
    }
}

CF_STATUS CF_MAC_IsValid(const CF_MAC_CTX *ctx) {
    if (!ctx)
        return CF_ERR_NULL_PTR;

    // Verify that the MAC pointer hasn’t been tampered with by checking it against the bound magic value.
    if ((ctx->magic ^ (uintptr_t)ctx->md) != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    return CF_SUCCESS;
}

CF_STATUS CF_MACOpts_Init(CF_MAC_OPTS *opts,
                          const uint8_t *iv, size_t iv_len,
                          const uint8_t *custom, size_t custom_len) {
    if (!opts)
        return CF_ERR_NULL_PTR;

    if (iv_len > CF_MAX_CUSTOMIZATION || custom_len > CF_MAX_CUSTOMIZATION)
        return CF_ERR_INVALID_LEN;

    CF_MACOpts_Reset(opts);

    opts->iv_len = iv_len;
    opts->custom_len = custom_len;

    if (iv && iv_len > 0)
        SECURE_MEMCPY(opts->iv, iv, iv_len);;

    if (custom && custom_len > 0)
        SECURE_MEMCPY(opts->custom, custom, custom_len);

    opts->magic = CF_CTX_MAGIC;

    return CF_SUCCESS;
}

CF_MAC_OPTS* CF_MACOpts_InitAlloc(const uint8_t *iv, size_t iv_len,
                                  const uint8_t *custom, size_t custom_len,
                                  CF_STATUS *status) {
    if (iv_len > CF_MAX_CUSTOMIZATION || custom_len > CF_MAX_CUSTOMIZATION) {
        if (status) *status = CF_ERR_INVALID_LEN;
        return NULL;
    }

    CF_MAC_OPTS *opts = (CF_MAC_OPTS *)SECURE_ALLOC(sizeof(CF_MAC_OPTS));
    if (!opts) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    CF_STATUS st = CF_MACOpts_Init(opts, iv, iv_len, custom, custom_len);
    if (st != CF_SUCCESS) {
        SECURE_FREE(opts, sizeof(CF_MAC_OPTS));
        if (status) *status = st;
        return NULL;
    }

    opts->isHeapAlloc = 1;
    if (status) *status = CF_SUCCESS;
    return opts;
}

CF_STATUS CF_MACOpts_Reset(CF_MAC_OPTS *opts) {
    if (!opts)
        return CF_ERR_NULL_PTR;

    SECURE_ZERO(opts->iv, sizeof(opts->iv));
    SECURE_ZERO(opts->custom, sizeof(opts->custom));

    opts->iv_len = 0;
    opts->custom_len = 0;

    return CF_SUCCESS;
}

CF_STATUS CF_MACOpts_Free(CF_MAC_OPTS **p_opts) {
    if (!p_opts || !*p_opts)
        return CF_ERR_NULL_PTR;

    CF_MAC_OPTS *opts = *p_opts;

    CF_STATUS ret = CF_MACOpts_Reset(opts);
    if (ret != CF_SUCCESS)
        return ret;

    if (opts->isHeapAlloc) {
        SECURE_FREE(opts, sizeof(*opts));
        *p_opts = NULL;
    }

    return CF_SUCCESS;
}
