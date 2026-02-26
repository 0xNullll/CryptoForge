/*
 * CryptoForge - cf_mac.c / High-level MAC context and utility implementation
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

#include "../../include/cf_api/cf_mac.h"

//
// Wrappers for all MACs
//

// HMAC
static CF_STATUS hmac_init_wrapper(CF_MAC_CTX *ctx, const CF_MAC_OPTS *opts) {
    UNUSED(opts);
    return ll_HMAC_Init((ll_HMAC_CTX *)ctx->mac_ctx, ctx->hash, ctx->key, ctx->key_len);
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
    return ll_HMAC_Verify((const CF_HASH *)ctx->hash, ctx->key, ctx->key_len, 
                          data, data_len, expected_tag, expected_tag_len);
}
static CF_STATUS hmac_clone_ctx_wrapper(CF_MAC_CTX *dest_ctx, const CF_MAC_CTX *src_ctx) {
    return ll_HMAC_CloneCtx((ll_HMAC_CTX *)dest_ctx->mac_ctx, (const ll_HMAC_CTX *)src_ctx->mac_ctx);
}

// KMAC
static CF_STATUS kmac_init_wrapper(CF_MAC_CTX *ctx, const CF_MAC_OPTS *opts) {
    return ll_KMAC_Init((ll_KMAC_CTX *)ctx->mac_ctx, ctx->key, ctx->key_len, opts ? opts->S : NULL, opts ? opts->S_len : 0, ctx->subflags);
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
                          opts->S, opts->S_len, expected_tag, expected_tag_len,
                          ctx->subflags);
}
static CF_STATUS kmac_clone_ctx_wrapper(CF_MAC_CTX *dest_ctx, const CF_MAC_CTX *src_ctx) {
    return ll_KMAC_CloneCtx((ll_KMAC_CTX *)dest_ctx->mac_ctx, (const ll_KMAC_CTX *)src_ctx->mac_ctx);
}

// CMAC
static CF_STATUS cmac_init_wrapper(CF_MAC_CTX *ctx, const CF_MAC_OPTS *opts) {
    UNUSED(opts);
    return ll_CMAC_Init((ll_CMAC_CTX *)ctx->mac_ctx, (const ll_AES_KEY *)ctx->key_ctx);
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
    return ll_CMAC_Verify((const ll_AES_KEY *)ctx->key_ctx, data, data_len,
                          expected_tag, expected_tag_len);
}
static CF_STATUS cmac_clone_ctx_wrapper(CF_MAC_CTX *dest_ctx, const CF_MAC_CTX *src_ctx) {
    return ll_CMAC_CloneCtx((ll_CMAC_CTX *)dest_ctx->mac_ctx, (const ll_CMAC_CTX *)src_ctx->mac_ctx);
}

// GMAC
static CF_STATUS gmac_init_wrapper(CF_MAC_CTX *ctx, const CF_MAC_OPTS *opts) {
    return ll_GMAC_Init((ll_GMAC_CTX *)ctx->mac_ctx, (const ll_AES_KEY *)ctx->key_ctx, opts ? opts->iv : NULL, opts ? opts->iv_len : 0);
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
    return ll_GMAC_Verify((const ll_AES_KEY *)ctx->key_ctx, opts->iv, opts->iv_len,
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
        .default_tag_len = CF_KMAC_DEFAULT_OUTPUT_LEN_128,
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
// AES-CMAC
//
static const CF_MAC *CF_get_aes_cmac(void) {
    static CF_MAC mac = {
        .id = CF_AES_CMAC,
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
// AES-GMAC
//
static const CF_MAC *CF_get_aes_gmac(void) {
    static CF_MAC mac = {
        .id = CF_AES_GMAC,
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

// Static table mapping MAC algorithm IDs to their respective getter
// functions. Used internally to retrieve a CF_MAC descriptor by flag.
static const CF_ALGO_ENTRY cf_mac_table[] = {
    { CF_HMAC,      (const void* (*)(void))CF_get_hmac     },
    { CF_KMAC_STD,  (const void* (*)(void))CF_get_kmac     },
    { CF_AES_CMAC,  (const void* (*)(void))CF_get_aes_cmac },
    { CF_AES_GMAC,  (const void* (*)(void))CF_get_aes_gmac },
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

    // Ensure the provided MAC ID is valid
    if (!CF_IS_MAC(mac->id))
        return CF_ERR_UNSUPPORTED;

    // Validate optional context flags if provided
    if (opts && opts->magic != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    // Ensure ctx->isHeapAlloc has a valid state (0 or 1)
    if (ctx->isHeapAlloc != 0 && ctx->isHeapAlloc != 1)
        return CF_ERR_CTX_UNINITIALIZED;

    // Reset context to a clean state before initialization
    CF_MAC_Reset(ctx);

    // Store core parameters in context
    ctx->mac      = mac;
    ctx->opts     = opts;
    ctx->key      = key;
    ctx->key_len  = key_len;
    ctx->subflags = subflags;

    // HMAC initialization
    if (CF_MAC_IS_HMAC(ctx->mac->id)) {
        // HMAC must have a hash subflag and cannot have KMAC flags
        if ((subflags & CF_MAC_KMAC_MASK) != 0)
            return CF_ERR_INVALID_PARAM;

        // Require a hash flag to be specified
        if ((subflags & CF_HASH_MASK) == 0)
            return CF_ERR_INVALID_PARAM;

        // Extended output functions (XOF) are not supported for HMAC
        if (CF_IS_XOF(subflags))
            return CF_ERR_UNSUPPORTED;

        // Retrieve hash function by subflag
        ctx->hash = CF_Hash_GetByFlag(subflags);
        if (!ctx->hash)
            return CF_ERR_UNSUPPORTED;

        // Set the default tag length from the hash output length
        ctx->tag_len = ctx->hash->default_out_len;

    }
    // KMAC initialization 
    else if (CF_MAC_IS_KMAC_STD(ctx->mac->id)) {
        // Must specify a KMAC type, cannot have standard hash flags
        if ((subflags & CF_MAC_KMAC_MASK) == 0)
            return CF_ERR_INVALID_PARAM;
        if ((subflags & CF_HASH_MASK) != 0)
            return CF_ERR_INVALID_PARAM;

    }
    // AES-based MACs (CMAC / GMAC)
    else if (CF_MAC_IS_AES_CMAC(ctx->mac->id) || CF_MAC_IS_AES_GMAC(ctx->mac->id)) {
        // Validate AES key length
        if (!CF_IS_CIPHER_AES_KEY_VALID(key_len))
            return CF_ERR_CIPHER_INVALID_KEY_LEN;

        // CMAC does not require an IV; GMAC requires a valid IV
        if (CF_MAC_IS_AES_GMAC(ctx->mac->id)) {
            if (!ctx->opts)
                return CF_ERR_CTX_OPTS_UNINITIALIZED;
        }

        // Set default MAC tag length
        ctx->tag_len = ctx->mac->default_tag_len;

        // Allocate memory for AES key context
        ctx->key_ctx = (void *)SECURE_ALLOC(ctx->mac->key_ctx_size);
        if (!ctx->key_ctx)
            return CF_ERR_ALLOC_FAILED;

        // Set AES encryption key; cleanup on failure
        if (!ll_AES_SetEncryptKey((ll_AES_KEY *)ctx->key_ctx, key, ctx->key_len)) {
            // Reset context on key expansion failure
            CF_MAC_Reset(ctx);
            return CF_ERR_CIPHER_KEY_SETUP;
        }

    }
    // Poly1305 MAC initialization
    else if (CF_MAC_IS_POLY1305(ctx->mac->id)) {
        // Key must be exactly 32 bytes
        if (key_len != CF_KEY_256_SIZE)
            return CF_ERR_MAC_INVALID_KEY_LEN;

        // Set default tag length
        ctx->tag_len = ctx->mac->default_tag_len;

    } else {
        // Unsupported MAC type
        return CF_ERR_UNSUPPORTED;
    }

    // Reject contexts with invalid size
    if (ctx->mac->ctx_size == 0) 
        return CF_ERR_CTX_CORRUPT;

    // Allocate memory for MAC context
    ctx->mac_ctx = (void *)SECURE_ALLOC(ctx->mac->ctx_size);
    if (!ctx->mac_ctx) {
        // Reset context on allocation failure
        CF_MAC_Reset(ctx);
        return CF_ERR_ALLOC_FAILED;
    }

    // Call the MAC-specific initialization function
    CF_STATUS st = ctx->mac->mac_init_fn(ctx, ctx->opts);
    if (st != CF_SUCCESS) {
        // Reset context on init failure
        CF_MAC_Reset(ctx);
        return st;
    }

    // Bind a per-context "magic" value for integrity checking
    // Detects accidental misuse or corruption of the context
    ctx->magic = CF_CTX_MAGIC ^ (uintptr_t)ctx->mac;

    return CF_SUCCESS;
}

CF_MAC_CTX* CF_MAC_InitAlloc(
    const CF_MAC *mac, const CF_MAC_OPTS *opts,
    const uint8_t *key, size_t key_len, uint32_t subflags,
    CF_STATUS *status) {
    if (!mac || !key) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    // Allocate memory for a new MAC context on the heap
    CF_MAC_CTX *ctx = (CF_MAC_CTX *)SECURE_ALLOC(sizeof(CF_MAC_CTX));
    if (!ctx) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Initialize the newly allocated MAC context
    CF_STATUS st = CF_MAC_Init(ctx, mac, opts, key, key_len, subflags);
    if (st != CF_SUCCESS) {
        if (status) *status = st;
        // Clean up on failure
        CF_MAC_Free(&ctx);
        return NULL;
    }

    // Mark context as heap-allocated for later safe cleanup
    ctx->isHeapAlloc = 1;
    
    if (status) *status = CF_SUCCESS;
    return ctx;
}


CF_STATUS CF_MAC_Update(CF_MAC_CTX *ctx, const uint8_t *data, size_t data_len) {
    if (!ctx)
        return CF_ERR_NULL_PTR;

    // Ensure the MAC context has been initialized
    if (!ctx->mac_ctx)
        return CF_ERR_CTX_UNINITIALIZED;

    // Verify context integrity using the bound "magic" value
    // Detects accidental corruption or misuse of the context
    if ((ctx->magic ^ (uintptr_t)ctx->mac) != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    // Prevent updates after finalization
    if (ctx->isFinalized)
        return CF_ERR_MAC_FINALIZED;

    // Call the low-level MAC update function
    return ctx->mac->mac_update_fn(ctx, data, data_len);
}

CF_STATUS CF_MAC_Final(CF_MAC_CTX *ctx, uint8_t *tag, size_t tag_len) {
    if (!ctx || !tag)
        return CF_ERR_NULL_PTR;

    // Ensure the MAC context and descriptor are initialized
    if (!ctx->mac || !ctx->mac_ctx)
        return CF_ERR_CTX_UNINITIALIZED;

    // Verify integrity of the context using the bound "magic" value
    // Detects accidental corruption or misuse of the context
    if ((ctx->magic ^ (uintptr_t)ctx->mac) != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    // Ensure the MAC context is properly initialized
    // For HMAC, md must be set; mac_ctx must exist for all MACs
    if ((!ctx->hash && CF_MAC_IS_HMAC(ctx->mac->id)) || !ctx->mac_ctx)
        return CF_ERR_CTX_UNINITIALIZED;

    // Validate requested tag length
    if (tag_len == 0)
        return CF_ERR_INVALID_LEN;

    // Handle previously finalized contexts
    if (!ctx->isFinalized) {
        // First finalization: store requested output length
        ctx->tag_len = tag_len;
    }

    // Subsequent finalizations
    if (ctx->isFinalized) {
        if (!CF_IS_KMAC_XOF(ctx->subflags) && tag_len != ctx->tag_len)
            return CF_ERR_INVALID_LEN;  // enforce fixed length for standard KMAC
    }

    // Validate tag length based on MAC type
    if (CF_MAC_IS_HMAC(ctx->mac->id)) {
        if (ctx->hash->default_out_len == 0)
            return CF_ERR_MAC_INVALID_TAG_LEN;

    } else if (CF_MAC_IS_AES_CMAC(ctx->mac->id)) {
        // CMAC requires tag length between 4 and AES block size
        if (tag_len < 4 || tag_len > AES_BLOCK_SIZE)
            return CF_ERR_MAC_INVALID_TAG_LEN;

    } else if (CF_MAC_IS_AES_GMAC(ctx->mac->id)) {
        // GMAC tag length must be valid for GCM
        if (!CF_IS_VALID_AEAD_GCM_TAG_SIZE(tag_len))
            return CF_ERR_MAC_INVALID_TAG_LEN;

    } else if (CF_MAC_IS_POLY1305(ctx->mac->id)) {
        // Poly1305 always uses a fixed 16-byte tag
        if (tag_len != LL_POLY1305_TAG_LEN)
            return CF_ERR_MAC_INVALID_TAG_LEN;
    }

    // Determine output length: prefer ctx->tag_len if set, otherwise user-specified
    size_t out_len = ctx->tag_len != 0 ? ctx->tag_len : tag_len;

    // Call the MAC-specific finalization function to compute the tag
    CF_STATUS st = ctx->mac->mac_final_fn(ctx, tag, out_len);
    if (st != CF_SUCCESS)
        return st;

    // Mark context as finalized to prevent accidental reuse
    ctx->isFinalized = 1;

    return CF_SUCCESS;
}

CF_STATUS CF_MAC_Reset(CF_MAC_CTX *ctx) {
    if (!ctx)
        return CF_ERR_NULL_PTR;

    // Ensure the MAC descriptor exists
    if (!ctx->mac)
        return CF_ERR_CTX_UNINITIALIZED;

    // Ensure the MAC type is valid
    if (!CF_IS_MAC(ctx->mac->id))
        return CF_ERR_UNSUPPORTED;

    CF_STATUS st = CF_SUCCESS;

    // Free the key context if it exists
    if (ctx->key_ctx) {
        if (ctx->mac->key_ctx_size == 0)
            return CF_ERR_CTX_CORRUPT;
        SECURE_FREE(ctx->key_ctx, ctx->mac->key_ctx_size);
    }

    // Free the MAC-specific context if it exists
    if (ctx->mac_ctx) {
        // Call the MAC-specific reset function to clear internal state
        st = ctx->mac->mac_reset_fn(ctx);
        if (st != CF_SUCCESS)
            return st;
        SECURE_FREE(ctx->mac_ctx, ctx->mac->ctx_size);
    }

    // Clear all context fields to prevent accidental reuse or leakage
    ctx->hash        = NULL;
    ctx->mac         = NULL;
    ctx->key         = NULL;
    ctx->key_len     = 0;
    ctx->tag_len     = 0;
    ctx->subflags    = 0;
    ctx->isFinalized = 0;
    ctx->magic       = 0;

    return st;
}

CF_STATUS CF_MAC_Free(CF_MAC_CTX **p_ctx) {
    if (!p_ctx || !*p_ctx)
        return CF_ERR_NULL_PTR;

    CF_MAC_CTX *ctx = *p_ctx;

    CF_MAC_Reset(ctx);

    if (ctx->isHeapAlloc) {
        SECURE_ZERO(ctx, sizeof(CF_MAC_CTX));
        *p_ctx = NULL; // make caller pointer NULL
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

    // Initialize the MAC context
    st = CF_MAC_Init(&ctx, mac, opts, key, key_len, subflags);
    // Check initialization success and context integrity
    if (st != CF_SUCCESS || (ctx.magic ^ (uintptr_t)ctx.mac) != CF_CTX_MAGIC)
        return st;

    // Call the MAC-specific verify function
    st = mac->mac_verify_fn(&ctx, data, data_len, expected_mac, expected_mac_len, opts);

    // Always securely clear the context to prevent sensitive data leakage
    CF_MAC_Reset(&ctx);

    return st;
}

CF_STATUS CF_MAC_Compute(const CF_MAC *mac,
                         const uint8_t *key, size_t key_len,
                         const uint8_t *data, size_t data_len,
                         uint8_t *tag, size_t tag_len,
                         const CF_MAC_OPTS *opts, uint32_t subflags) {
    if (!mac || !key || !tag)
        return CF_ERR_NULL_PTR;

    // Stack-allocated MAC context for one-shot computation
    CF_MAC_CTX ctx = {0};
    CF_STATUS st = CF_SUCCESS;

    // Initialize MAC context with descriptor, key, options, and subflags
    st = CF_MAC_Init(&ctx, mac, opts, key, key_len, subflags);

    // Verify initialization success and context integrity
    // Magic check detects accidental corruption or misuse
    if (st != CF_SUCCESS || (ctx.magic ^ (uintptr_t)ctx.mac) != CF_CTX_MAGIC)
        goto cleanup;

    // Process input data through MAC update phase
    // This feeds the entire message into the MAC state
    st = CF_MAC_Update(&ctx, data, data_len);

    // Re-verify context integrity after update
    // Ensures state was not corrupted during processing
    if (st != CF_SUCCESS || (ctx.magic ^ (uintptr_t)ctx.mac) != CF_CTX_MAGIC)
        goto cleanup;

    // Finalize MAC computation and produce authentication tag
    // tag_len must match algorithm requirements (or allowed truncated size)
    st = CF_MAC_Final(&ctx, tag, tag_len);

cleanup:
    // Securely clear context regardless of success or failure
    CF_MAC_Reset(&ctx);

    return st;
}

CF_STATUS CF_MAC_CloneCtx(CF_MAC_CTX *dst, const CF_MAC_CTX *src) {
    if (!dst || !src)
        return CF_ERR_NULL_PTR;

    if ((src->magic ^ (uintptr_t)src->mac) != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    // Start with a clean slate
    CF_MAC_Reset(dst);

    // Copy metadata
    dst->magic       = src->magic;
    dst->mac         = src->mac;
    dst->hash        = src->hash;
    dst->opts        = src->opts;
    dst->tag_len     = src->tag_len;
    dst->subflags    = src->subflags;
    dst->isFinalized = src->isFinalized;
    dst->isHeapAlloc = 0;
    
    // Copy key pointer and length (shallow copy)
    dst->key     = src->key;
    dst->key_len = src->key_len;

    CF_STATUS st = CF_SUCCESS;

    // Deep copy key_ctx if it exists
    if (src->key_ctx) {
        if (src->mac->key_ctx_size == 0)
            return CF_ERR_CTX_CORRUPT;

        dst->key_ctx = SECURE_ALLOC(src->mac->key_ctx_size);
        if (!dst->key_ctx) {
            st = CF_ERR_ALLOC_FAILED;
            goto cleanup;
        }
        SECURE_MEMCPY(dst->key_ctx, src->key_ctx, src->mac->key_ctx_size);
    }

    // Deep copy low-level MAC context
    if (src->mac_ctx) {
        if (src->mac->ctx_size == 0) {
            st = CF_ERR_CTX_CORRUPT;
            goto cleanup;
        }

        dst->mac_ctx = SECURE_ALLOC(src->mac->ctx_size);
        if (!dst->mac_ctx) {
            st = CF_ERR_ALLOC_FAILED;
            goto cleanup;
        }

        st = src->mac->mac_clone_ctx_fn(dst, src);
        if (st != CF_SUCCESS)
            goto cleanup;
    }

    return st;

cleanup:
    // Cleanup any partially allocated memory
    if (dst->key_ctx && src->mac->key_ctx_size)
        SECURE_FREE(dst->key_ctx, src->mac->key_ctx_size);
    if (dst->mac_ctx && src->mac->ctx_size)
        SECURE_FREE(dst->mac_ctx, src->mac->ctx_size);

    return st;
}

CF_MAC_CTX *CF_MAC_CloneCtxAlloc(const CF_MAC_CTX *src, CF_STATUS *status) {
    if (!src) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    CF_MAC_CTX *dst = (CF_MAC_CTX *)SECURE_ALLOC(sizeof(CF_MAC_CTX));
    if (!dst) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Deep copy contents
    CF_STATUS ret = CF_MAC_CloneCtx(dst, src);
    if (ret != CF_SUCCESS) {
        if (status) *status = ret;
        CF_MAC_Free(&dst);
        return NULL;
    }

    // cloned context is heap-allocated
    dst->isHeapAlloc = 1;

    if (status) *status = CF_SUCCESS;
    return dst;
}

CF_STATUS CF_MAC_ValidateCtx(const CF_MAC_CTX *ctx) {
    if (!ctx)
        return CF_ERR_NULL_PTR;

    // Verify that the MAC pointer hasn’t been tampered with by checking it against the bound magic value.
    if ((ctx->magic ^ (uintptr_t)ctx->mac) != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    return CF_SUCCESS;
}

const char* CF_MAC_GetName(const CF_MAC *ctx) {
    if (!ctx)
        return NULL;

    switch (ctx->id) {
        case CF_HMAC:     return "HMAC";
        case CF_KMAC_STD: return "KMAC";
        case CF_AES_CMAC: return "AES-CMAC";
        case CF_AES_GMAC: return "AES-GMAC";
        case CF_POLY1305: return "POLY-1305";

        default:
            return "UNKNOWN-MAC";
    }
}

const char* CF_MAC_GetFullName(const CF_MAC_CTX *ctx) {
    if (!ctx || !ctx->mac)
        return NULL;

    switch (ctx->mac->id) {
        case CF_HMAC:
            switch (ctx->subflags) {
                case CF_MD5:        return "HMAC-MD-5";
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

        case CF_AES_CMAC:
            switch (ctx->key_len) {
                case AES_128_KEY_SIZE: return "AES-CMAC-128";
                case AES_192_KEY_SIZE: return "AES-CMAC-192";
                case AES_256_KEY_SIZE: return "AES-CMAC-256";
                default:               return "AES-CMAC-UNKNOWN";
            }

        case CF_AES_GMAC:
            switch (ctx->key_len) {
                case AES_128_KEY_SIZE: return "AES-GMAC-128";
                case AES_192_KEY_SIZE: return "AES-GMAC-192";
                case AES_256_KEY_SIZE: return "AES-GMAC-256";
                default:               return "AES-GMAC-UNKNOWN";
            }

        case CF_POLY1305:          return "POLY-1305";

        default:
            return "UNKNOWN-MAC";
    }
}

bool CF_MAC_IsValidKeyLength(const CF_MAC *mac, size_t key_len) {
    if (!mac || key_len == 0)
        return false;

    if (CF_MAC_IS_HMAC(mac->id) || CF_MAC_IS_KMAC_STD(mac->id)) {
        return true;
    } else if (CF_MAC_IS_AES_CMAC(mac->id) || CF_MAC_IS_AES_GMAC(mac->id)) {
        if (CF_IS_CIPHER_AES_KEY_VALID(key_len))
            return true;
    } else if (CF_MAC_IS_POLY1305(mac->id)) {
        if (key_len == CF_KEY_256_SIZE)
            return true;
    }

    return false;
}

bool CF_MAC_IsValidTagLength(const CF_MAC *mac, size_t tag_len) {
    if (!mac || tag_len == 0)
        return false;

    if (CF_MAC_IS_HMAC(mac->id) || CF_MAC_IS_KMAC_STD(mac->id)) {
        return true;
    } else if (CF_MAC_IS_AES_CMAC(mac->id)) {
        if (tag_len < AES_BLOCK_SIZE || tag_len > 4)
            return true;
    } else if (CF_MAC_IS_AES_GMAC(mac->id)) {
       if (CF_IS_VALID_AEAD_GCM_TAG_SIZE(tag_len))
        return true;
    } else if (CF_MAC_IS_POLY1305(mac->id)) {
        if (tag_len == CF_AEAD_TAG_128_SIZE)
            return true;
    }

    return false;
}

const size_t* CF_MAC_GetValidKeySizes(const CF_MAC *mac, size_t *count) {
    if (!mac || !count)
        return NULL;

    static const size_t aes_sizes[3] = {CF_KEY_128_SIZE, CF_KEY_192_SIZE, CF_KEY_256_SIZE};
    static const size_t poly1305_sizes[1] = {CF_KEY_256_SIZE};

    if (CF_MAC_IS_HMAC(mac->id) || CF_MAC_IS_KMAC_STD(mac->id)) {
        *count = 0;
        return 0;
    } else if (CF_MAC_IS_AES_CMAC(mac->id) || CF_MAC_IS_AES_GMAC(mac->id)) {
        *count = 3;
        return aes_sizes;
    } else if (CF_MAC_IS_POLY1305(mac->id)) {
        *count = 1;
        return poly1305_sizes;
    }

    *count = 0;
    return NULL;
}

const size_t* CF_MAC_GetValidTagSizes(const CF_MAC *mac, size_t *count) {
    if (!mac || !count)
        return NULL;

    static const size_t aes_cmac_sizes[13] = {4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static const size_t aes_gmac_sizes[4] = {CF_AEAD_TAG_32_SIZE, CF_AEAD_TAG_64_SIZE, CF_AEAD_TAG_96_SIZE, CF_AEAD_TAG_128_SIZE};
    static const size_t poly1305_sizes[1] = {CF_AEAD_TAG_128_SIZE};

    if (CF_MAC_IS_HMAC(mac->id) || CF_MAC_IS_KMAC_STD(mac->id)) {
        *count = 0;
        return NULL;
    } else if (CF_MAC_IS_AES_CMAC(mac->id)) {
        *count = 13;
        return aes_cmac_sizes;
    } else if (CF_MAC_IS_AES_GMAC(mac->id)) {
        *count = 4;
        return aes_gmac_sizes;
    } else if (CF_MAC_IS_POLY1305(mac->id)) {
        *count = 1;
        return poly1305_sizes;
    }

    *count = 0;
    return NULL;
}

CF_STATUS CF_MACOpts_Init(CF_MAC_OPTS *opts,
                          const uint8_t *iv, size_t iv_len,
                          const uint8_t *custom, size_t custom_len) {
    if (!opts)
        return CF_ERR_NULL_PTR;

    if (iv_len > AES_BLOCK_SIZE)
        return CF_ERR_INVALID_LEN;

    CF_MACOpts_Reset(opts);

    // Shallow copy (caller manages lifetime)
    opts->S     = custom;
    opts->S_len = custom_len;

    // Deep copy of IV
    if (iv && iv_len > 0) {
        SECURE_MEMCPY(opts->iv, iv, iv_len);
        opts->iv_len = iv_len;
    }
    
    opts->magic = CF_CTX_MAGIC;

    return CF_SUCCESS;
}

CF_MAC_OPTS* CF_MACOpts_InitAlloc(const uint8_t *iv, size_t iv_len,
                                  const uint8_t *custom, size_t custom_len,
                                  CF_STATUS *status) {
    if (iv_len > AES_BLOCK_SIZE) {
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
        if (status) *status = st;
        // Clean up on failure
        CF_MACOpts_Free(&opts);
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

    opts->S      = NULL;
    opts->S_len  = 0;
    opts->iv_len = 0;
    opts->magic  = 0;

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
        *p_opts = NULL; // make caller pointer NULL
    }

    return CF_SUCCESS;
}

CF_STATUS CF_MACOpts_CloneCtx(CF_MAC_OPTS *dst, const CF_MAC_OPTS *src) {
    if (!dst || !src)
        return CF_ERR_NULL_PTR;

    if (src->magic != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    // Start with a clean slate
    CF_MACOpts_Reset(dst);

    // Shallow copy (caller manages lifetime)
    dst->S     = src->S;
    dst->S_len = src->S_len;

    // Deep copy IV
    if (src->iv_len != 0) {
        SECURE_MEMCPY(dst->iv, src->iv, sizeof(dst->iv));
        dst->iv_len = src->iv_len;
    }

    dst->magic       = src->magic;
    dst->isHeapAlloc = 0;

    return CF_SUCCESS;
}

CF_MAC_OPTS* CF_MACOpts_CloneCtxAlloc(const CF_MAC_OPTS *src, CF_STATUS *status) {
    if (!src) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    CF_MAC_OPTS *dst = (CF_MAC_OPTS *)SECURE_ALLOC(sizeof(CF_MAC_OPTS));
    if (!dst) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Deep copy contents
    CF_STATUS ret = CF_MACOpts_CloneCtx(dst, src);
    if (ret != CF_SUCCESS) {
        if (status) *status = ret;
        CF_MACOpts_Free(&dst);
        return NULL;
    }

    // cloned context is heap-allocated
    dst->isHeapAlloc = 1;

    if (status) *status = CF_SUCCESS;
    return dst;
}