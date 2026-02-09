/*
 * CryptoForge - cf_kdf.c / High-level KDF context and utility implementation
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against WyChaProof test vectors. No hardware optimizations. Use with caution.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#include "../../include/cf_api/cf_kdf.h"


//
// Wrappers for all kdfs
//

// typedef struct _CF_KDF {
//     uint32_t id;
//     size_t ctx_size;
//     size_t default_out_len;

//     CF_STATUS (*kdf_init_fn)(struct _CF_KDF_CTX *ctx);

//     CF_STATUS (*kdf_extract_fn)(struct _CF_KDF_CTX *ctx,
//                                 const uint8_t *key, size_t key_len,
//                                 const struct _CF_KDF_OPTS *opts);

//     CF_STATUS (*kdf_expand_fn)(struct _CF_KDF_CTX *ctx,
//                                uint8_t *out, size_t out_len);

//     CF_STATUS (*kdf_reset_fn)(struct _CF_KDF_CTX *ctx);

//     CF_STATUS (*kdf_clone_ctx_fn)(struct _CF_KDF_CTX *ctx_dest,
//                               const struct _CF_KDF_CTX *ctx_src);
// } CF_KDF;

// HKDF
static CF_STATUS hkdf_init_wrapper(CF_KDF_CTX *ctx, const CF_KDF_OPTS *opts) {
    return ll_HKDF_Init((ll_HKDF_CTX *)ctx->kdf_ctx, ctx->md, opts->info, opts->info_len);
}

static CF_STATUS hkdf_extract_wrapper(CF_KDF_CTX *ctx, const CF_KDF_OPTS *opts) {
    return ll_HKDF_Extract((ll_HKDF_CTX *)ctx->kdf_ctx, opts->salt, opts->salt_len, ctx->key, ctx->key_len);
}

static CF_STATUS hkdf_extract_wrapper(CF_KDF_CTX *ctx, uint8_t *out, const CF_KDF_OPTS *opts, bool new_info) {
    return ll_HKDF_Expand((ll_HKDF_CTX *)ctx->kdf_ctx, opts->salt, opts->salt_len, new_info ? opts->info : NULL, new_info ? opts->info_len : 0);
}
static CF_STATUS hkdf_reset_wrapper(CF_KDF_CTX *ctx) {
    return ll_HKDF_Reset((ll_HKDF_CTX *)ctx->kdf_ctx);
}
static CF_STATUS hkdf_clone_ctx_wrapper(CF_KDF_CTX *ctx_dest, const CF_KDF_CTX *ctx_src) {
    return ll_HKDF_CloneCtx((ll_HKDF_CTX *)ctx_dest->kdf_ctx, (const ll_HKDF_CTX *)ctx_src->kdf_ctx);
}


const CF_KDF *CF_KDF_GetByFlag(uint32_t kdf_flag) {

}