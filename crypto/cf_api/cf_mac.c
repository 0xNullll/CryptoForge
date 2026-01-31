/*
 * CryptoForge - <short description of this file/module>
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License in the file LICENSE in the
 * source distribution or at:
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * This software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
 * OR CONDITIONS OF ANY KIND, either express or implied. See the License
 * for the specific language governing permissions and limitations under
 * the License.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#include "../../include/cf_api/cf_mac.h"

//
// Wrappers for all MACs
//

// HMAC
static void *hmac_init_alloc_wrapper(CF_MAC_CTX *ctx, const CF_MAC_OPTS *opts, CF_STATUS *status) {
    UNUSED(opts);
    return ll_HMAC_InitAlloc(ctx->md, ctx->key, ctx->key_len, status);
}
static CF_STATUS hmac_update_wrapper(CF_MAC_CTX *ctx, const uint8_t *data, size_t data_len) {
    return ll_HMAC_Update((ll_HMAC_CTX *)ctx->mac_ctx, data, data_len);
}
static CF_STATUS hmac_final_wrapper(CF_MAC_CTX *ctx, uint8_t *tag, size_t tag_len) {
    return ll_HMAC_Final((ll_HMAC_CTX *)ctx->mac_ctx, tag, tag_len);
}
static CF_STATUS hmac_free_wrapper(CF_MAC_CTX *ctx) {
    return ll_HMAC_Free((ll_HMAC_CTX **)ctx->mac_ctx);
}

// KMAC
static void *kmac_init_alloc_wrapper(CF_MAC_CTX *ctx, const CF_MAC_OPTS *opts, CF_STATUS *status) {
    return ll_KMAC_InitAlloc(ctx->key, ctx->key_len, opts->custom, opts->custom_len, ctx->subflags, status);
}

static CF_STATUS kmac_update_wrapper(CF_MAC_CTX *ctx, const uint8_t *data, size_t data_len) {
    return ll_KMAC_Update((ll_KMAC_CTX *)ctx->mac_ctx, data, data_len);
}
static CF_STATUS kmac_final_wrapper(CF_MAC_CTX *ctx, uint8_t *tag, size_t tag_len) {
    return ll_KMAC_Final((ll_KMAC_CTX *)ctx->mac_ctx, tag, tag_len);
}
static CF_STATUS kmac_free_wrapper(CF_MAC_CTX *ctx) {
    return ll_KMAC_Free((ll_KMAC_CTX **)ctx->mac_ctx);
}

// CMAC
static void *cmac_init_alloc_wrapper(CF_MAC_CTX *ctx, const CF_MAC_OPTS *opts, CF_STATUS *status) {
    return ll_CMAC_InitAlloc((const ll_AES_KEY *)ctx->cipher_key, status);
}
static CF_STATUS cmac_update_wrapper(CF_MAC_CTX *ctx, const uint8_t *data, size_t data_len) {
    return ll_CMAC_Update((ll_CMAC_CTX *)ctx->mac_ctx, data, data_len);
}
static CF_STATUS cmac_final_wrapper(CF_MAC_CTX *ctx, uint8_t *tag, size_t tag_len) {
    return ll_CMAC_Final((ll_CMAC_CTX *)ctx->mac_ctx, tag, tag_len);
}
static CF_STATUS cmac_free_wrapper(CF_MAC_CTX *ctx) {
    return ll_CMAC_Free((ll_CMAC_CTX **)ctx->mac_ctx);
}

// GMAC
static void *gmac_init_alloc_wrapper(CF_MAC_CTX *ctx, const CF_MAC_OPTS *opts, CF_STATUS *status) {
    return ll_GMAC_InitAlloc((const ll_AES_KEY *)ctx->cipher_key, opts->iv, opts->iv_len, status);
}
static CF_STATUS gmac_update_wrapper(CF_MAC_CTX *ctx, const uint8_t *data, size_t data_len) {
    return ll_GMAC_Update((ll_GMAC_CTX *)ctx->mac_ctx, data, data_len);
}
static CF_STATUS gmac_final_wrapper(CF_MAC_CTX *ctx, uint8_t *tag, size_t tag_len) {
    return ll_GMAC_Final((ll_GMAC_CTX *)ctx->mac_ctx, tag, tag_len);
}
static CF_STATUS gmac_free_wrapper(CF_MAC_CTX *ctx) {
    return ll_GMAC_Free((ll_GMAC_CTX **)ctx->mac_ctx);
}

// --- CF_MAC Return Functions ---

//
// HMAC
//
static const CF_MAC *CF_get_hmac(void) {
    static CF_MAC md = {
        .id = CF_HMAC,
        .ctx_size = sizeof(ll_HMAC_CTX),
        .key_ctx_size = 0,
        .mac_init_alloc_fn = hmac_init_alloc_wrapper,
        .mac_update_fn = hmac_update_wrapper,
        .mac_final_fn = hmac_final_wrapper,
        .mac_free_fn = hmac_free_wrapper
    };
    return &md;
}

//
// KMAC
//
static const CF_MAC *CF_get_kmac(void) {
    static CF_MAC md = {
        .id = CF_KMAC,
        .ctx_size = sizeof(ll_KMAC_CTX),
        .key_ctx_size = 0,
        .mac_init_alloc_fn = kmac_init_alloc_wrapper,
        .mac_update_fn = kmac_update_wrapper,
        .mac_final_fn = kmac_final_wrapper,
        .mac_free_fn = kmac_free_wrapper
    };
    return &md;
}

//
// CMAC
//
static const CF_MAC *CF_get_cmac(void) {
    static CF_MAC md = {
        .id = CF_CMAC,
        .ctx_size = sizeof(ll_CMAC_CTX),
        .key_ctx_size = sizeof(ll_AES_KEY),
        .mac_init_alloc_fn = cmac_init_alloc_wrapper,
        .mac_update_fn = cmac_update_wrapper,
        .mac_final_fn = cmac_final_wrapper,
        .mac_free_fn = cmac_free_wrapper
    };
    return &md;
}

//
// GMAC
//
static const CF_MAC *CF_get_gmac(void) {
    static CF_MAC md = {
        .id = CF_GMAC,
        .ctx_size = sizeof(ll_GMAC_CTX),
        .key_ctx_size = sizeof(ll_AES_KEY),
        .mac_init_alloc_fn = gmac_init_alloc_wrapper,
        .mac_update_fn = gmac_update_wrapper,
        .mac_final_fn = gmac_final_wrapper,
        .mac_free_fn = gmac_free_wrapper
    };
    return &md;
}

// Table of all supported MACs
static const CF_ALGO_ENTRY cf_mac_table[] = {
    { CF_HMAC,  (const void* (*)(void))CF_get_hmac },
    { CF_KMAC,  (const void* (*)(void))CF_get_kmac },
    { CF_CMAC,  (const void* (*)(void))CF_get_cmac },
    { CF_GMAC,  (const void* (*)(void))CF_get_gmac }
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

CF_STATUS CF_MAC_Init(CF_MAC_CTX *ctx, const CF_MAC *mac,
                      const CF_MAC_OPTS *opts,
                      const uint8_t *key, size_t key_len,
                      uint32_t subflags) {
    CF_STATUS status = CF_SUCCESS;

    if (!ctx || !mac || !key)
        return CF_ERR_NULL_PTR;

    if (ctx->isHeapAlloc != 0 && ctx->isHeapAlloc != 1)
        return CF_ERR_CTX_UNINITIALIZED;

    // Discard invalid or empty subflags
    if ((subflags & CF_MAC_SUBFLAG_MASK) == 0)
        return CF_ERR_INVALID_PARAM;

    // Fresh cleanup
    CF_MAC_Reset(ctx);

    ctx->mac      = mac;
    ctx->key      = key;
    ctx->key_len  = key_len;
    ctx->subflags = subflags;

    // Hash selection is only valid for HMAC-like MACs
    if ((subflags & CF_MAC_HASH_MASK) != 0) {

        if (!CF_MAC_IS_HMAC(mac->id))
            return CF_ERR_INVALID_PARAM;

        ctx->md = CF_MD_GetByFlag(subflags);
        if (!ctx->md) {
            status = CF_ERR_UNSUPPORTED;
            goto cleanup;
        }
    }

    // CMAC / GMAC need an AES key schedule
    if (CF_MAC_IS_CMAC(mac->id) || CF_MAC_IS_GMAC(mac->id)) {

        if (!CF_IS_AES_KEY_VALID(key_len)) {
            status = CF_ERR_CIPHER_INVALID_KEY_LEN;
            goto cleanup;
        }

        ll_AES_KEY *cipher_key = (ll_AES_KEY *)SECURE_ALLOC(mac->key_ctx_size);

        if (!cipher_key) {
            status = CF_ERR_ALLOC_FAILED;
            goto cleanup;
        }

        if (!ll_AES_SetEncryptKey(cipher_key, key, key_len)) {
            SECURE_FREE(cipher_key, mac->key_ctx_size);
            status = CF_ERR_CIPHER_KEY_SETUP;
            goto cleanup;
        }

        // Library-owned, immutable key schedule
        ctx->cipher_key = cipher_key;
    }

    // Allocate / initialize MAC internal context
    ctx->mac_ctx = NULL;
    status = CF_SUCCESS;

    ctx->mac_ctx = mac->mac_init_alloc_fn(ctx, opts, &status);

    if (status != CF_SUCCESS || !ctx->mac_ctx)
        goto cleanup;

    return CF_SUCCESS;

cleanup:
    CF_MAC_Reset(ctx);
    return status;
}


CF_MAC_CTX* CF_MAC_InitAlloc(const CF_MAC *mac, const CF_MAC_OPTS *opts,
                                    const uint8_t *key, size_t key_len, uint32_t subflags,
                                    CF_STATUS *status) {
                                        
                                    }

CF_STATUS CF_MAC_Update(CF_MAC_CTX *ctx, const uint8_t *data, size_t data_len) {

}
CF_STATUS CF_MAC_Final(CF_MAC_CTX *ctx, uint8_t *tag, size_t tag_len) {

}

CF_STATUS CF_MAC_Reset(CF_MAC_CTX *ctx) {

}
CF_STATUS CF_MAC_Free(CF_MAC_CTX **p_ctx) {

}

// ============================
// One-shot MAC computation
// ============================
CF_STATUS CF_MAC_Compute(const CF_MAC *mac,
                                const uint8_t *key, size_t key_len,
                                const uint8_t *data, size_t data_len,
                                uint8_t *tag, size_t tag_len,
                                const CF_MAC_OPTS *opts) {

                                }


const char* CF_MAC_GetName(const CF_MAC *ctx) {

}

// ============================
// Cloning
// ============================
CF_STATUS CF_MAC_CloneCtx(CF_MAC_CTX *dst, const CF_MAC_CTX *src) {

}
CF_MAC_CTX* CF_MAC_CloneCtxAlloc(const CF_MAC_CTX *src, CF_STATUS *status) {

}

// ============================
// Optional parameters init / cleanup
// ============================
CF_STATUS CF_MACOpts_Init(CF_MAC_OPTS *opts,
                                 const uint8_t *iv, size_t iv_len,
                                 const uint8_t *custom, size_t custom_len) {

                                 }

CF_MAC_OPTS* CF_MACOpts_InitAlloc(const uint8_t *iv, size_t iv_len,
                                         const uint8_t *custom, size_t custom_len,
                                         CF_STATUS *status) {

                                         }

void CF_MACOpts_Reset(CF_MAC_OPTS *opts) {

}
void CF_MACOpts_Free(CF_MAC_OPTS **p_opts) {

}

CF_STATUS CF_MACOpts_CloneCtx(CF_MAC_OPTS *dst, const CF_MAC_OPTS *src) {

}
CF_MAC_OPTS* CF_MACOpts_CloneCtxAlloc(const CF_MAC_OPTS *src, CF_STATUS *status) {

}
