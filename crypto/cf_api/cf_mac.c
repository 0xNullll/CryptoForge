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
    return ll_HMAC_InitAlloc(opts->md, ctx->key, ctx->key_len, status);
}
static CF_STATUS hmac_update_wrapper(CF_MAC_CTX *ctx, const uint8_t *data, size_t data_len) {
    return ll_HMAC_Update((ll_HMAC_CTX *)ctx->mac_ctx, data, data_len);
}
static CF_STATUS hmac_final_wrapper(CF_MAC_CTX *ctx, uint8_t *tag, size_t tag_len) {
    return ll_HMAC_Final((ll_HMAC_CTX *)ctx->mac_ctx, tag, tag_len);
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

// CMAC
static void *cmac_init_alloc_wrapper(CF_MAC_CTX *ctx, const CF_MAC_OPTS *opts, CF_STATUS *status) {
    UNUSED(ctx);
    return ll_CMAC_InitAlloc((const ll_AES_KEY *)opts->cipher_key, status);
}
static CF_STATUS cmac_update_wrapper(CF_MAC_CTX *ctx, const uint8_t *data, size_t data_len) {
    return ll_CMAC_Update((ll_CMAC_CTX *)ctx->mac_ctx, data, data_len);
}
static CF_STATUS cmac_final_wrapper(CF_MAC_CTX *ctx, uint8_t *tag, size_t tag_len) {
    return ll_CMAC_Final((ll_CMAC_CTX *)ctx->mac_ctx, tag, tag_len);
}

// GMAC
static void *gmac_init_alloc_wrapper(CF_MAC_CTX *ctx, const CF_MAC_OPTS *opts, CF_STATUS *status) {
    UNUSED(ctx);
    return ll_GMAC_InitAlloc(opts->cipher_key, opts->iv, opts->iv_len, status);
}
static CF_STATUS gmac_update_wrapper(CF_MAC_CTX *ctx, const uint8_t *data, size_t data_len) {
    return ll_GMAC_Update((ll_GMAC_CTX *)ctx->mac_ctx, data, data_len);
}
static CF_STATUS gmac_final_wrapper(CF_MAC_CTX *ctx, uint8_t *tag, size_t tag_len) {
    return ll_GMAC_Final((ll_GMAC_CTX *)ctx->mac_ctx, tag, tag_len);
}

// --- CF_MAC Return Functions ---

//
// HMAC
//
static const CF_MAC *CF_get_hmac(void) {
    static CF_MAC md = {
        .id = CF_HMAC,
        .tag_size = 0,
        .block_size = 0,
        .ctx_size = sizeof(ll_HMAC_CTX),
        .opts_ctx_size = sizeof(CF_MAC_OPTS),
        .default_out_len = 0,
        .mac_init_alloc_fn = hmac_init_alloc_wrapper,
        .mac_update_fn = hmac_update_wrapper,
        .mac_final_fn = hmac_final_wrapper,
    };
    return &md;
}

//
// KMAC
//
static const CF_MAC *CF_get_kmac(void) {
    static CF_MAC md = {
        .id = CF_KMAC,
        .tag_size = 0,
        .block_size = 0,
        .ctx_size = sizeof(ll_KMAC_CTX),
        .opts_ctx_size = sizeof(CF_MAC_OPTS),
        .default_out_len = 0,
        .mac_init_alloc_fn = kmac_init_alloc_wrapper,
        .mac_update_fn = kmac_update_wrapper,
        .mac_final_fn = kmac_final_wrapper,
    };
    return &md;
}

//
// CMAC
//
static const CF_MAC *CF_get_cmac(void) {
    static CF_MAC md = {
        .id = CF_CMAC,
        .tag_size = 0,
        .block_size = 0,
        .ctx_size = sizeof(ll_CMAC_CTX),
        .opts_ctx_size = sizeof(CF_MAC_OPTS),
        .default_out_len = 0,
        .mac_init_alloc_fn = cmac_init_alloc_wrapper,
        .mac_update_fn = cmac_update_wrapper,
        .mac_final_fn = cmac_final_wrapper,
    };
    return &md;
}

//
// GMAC
//
static const CF_MAC *CF_get_gmac(void) {
    static CF_MAC md = {
        .id = CF_GMAC,
        .tag_size = 0,
        .block_size = 0,
        .ctx_size = sizeof(ll_GMAC_CTX),
        .opts_ctx_size = sizeof(CF_MAC_OPTS),
        .default_out_len = 0,
        .mac_init_alloc_fn = gmac_init_alloc_wrapper,
        .mac_update_fn = gmac_update_wrapper,
        .mac_final_fn = gmac_final_wrapper,
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

const CF_MAC *CF_MACByFlag(uint32_t algo_flag) {
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
