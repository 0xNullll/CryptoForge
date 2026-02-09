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

// HKDF
static CF_STATUS hkdf_init_wrapper(CF_KDF_CTX *ctx, const CF_KDF_OPTS *opts) {
    return ll_HKDF_Init((ll_HKDF_CTX *)ctx->kdf_ctx, ctx->md, opts->info, opts->info_len);
}

static CF_STATUS hkdf_extract_wrapper(CF_KDF_CTX *ctx, const CF_KDF_OPTS *opts) {
    return ll_HKDF_Extract((ll_HKDF_CTX *)ctx->kdf_ctx, opts->salt, opts->salt_len, ctx->ikm, ctx->ikm_len);
}

static CF_STATUS hkdf_expand_wrapper(CF_KDF_CTX *ctx, uint8_t *out, size_t out_len, const CF_KDF_OPTS *opts, bool new_info) {
    return ll_HKDF_Expand((ll_HKDF_CTX *)ctx->kdf_ctx, out, out_len , new_info ? opts->info : NULL, new_info ? opts->info_len : 0);
}
static CF_STATUS hkdf_reset_wrapper(CF_KDF_CTX *ctx) {
    return ll_HKDF_Reset((ll_HKDF_CTX *)ctx->kdf_ctx);
}
static CF_STATUS hkdf_clone_ctx_wrapper(CF_KDF_CTX *ctx_dest, const CF_KDF_CTX *ctx_src) {
    return ll_HKDF_CloneCtx((ll_HKDF_CTX *)ctx_dest->kdf_ctx, (const ll_HKDF_CTX *)ctx_src->kdf_ctx);
}

// PBKDF2
static CF_STATUS pbkdf2_init_wrapper(CF_KDF_CTX *ctx, const CF_KDF_OPTS *opts) {
    UNUSED(opts);
    return ll_PBKDF2_Init((ll_PBKDF2_CTX *)ctx->kdf_ctx, ctx->md, ctx->ikm, ctx->ikm_len);
}

static CF_STATUS pbkdf2_extract_wrapper(CF_KDF_CTX *ctx, const CF_KDF_OPTS *opts) {
    return ll_PBKDF2_Extract((ll_PBKDF2_CTX *)ctx->kdf_ctx, opts->salt, opts->salt_len);
}

static CF_STATUS pbkdf2_expand_wrapper(CF_KDF_CTX *ctx, uint8_t *out, size_t out_len, const CF_KDF_OPTS *opts, bool new_info) {
    UNUSED(new_info);
    return ll_PBKDF2_Expand((ll_PBKDF2_CTX *)ctx->kdf_ctx, out, out_len, opts->iterations);
}
static CF_STATUS pbkdf2_reset_wrapper(CF_KDF_CTX *ctx) {
    return ll_PBKDF2_Reset((ll_PBKDF2_CTX *)ctx->kdf_ctx);
}
static CF_STATUS pbkdf2_clone_ctx_wrapper(CF_KDF_CTX *ctx_dest, const CF_KDF_CTX *ctx_src) {
    return ll_PBKDF2_CloneCtx((ll_PBKDF2_CTX *)ctx_dest->kdf_ctx, (const ll_PBKDF2_CTX *)ctx_src->kdf_ctx);
}

// KMAC-XOF
static CF_STATUS kkdf_xof_init_wrapper(CF_KDF_CTX *ctx, const CF_KDF_OPTS *opts) {
    return ll_KMAC_Init((ll_KMAC_CTX *)ctx->kdf_ctx, ctx->ikm, ctx->ikm_len, opts->custom, opts->custom_len, ctx->subflags);
}

static CF_STATUS kkdf_xof_extract_wrapper(CF_KDF_CTX *ctx, const CF_KDF_OPTS *opts) {
    return ll_KMAC_Update((ll_KMAC_CTX *)ctx->kdf_ctx, opts->info, opts->info_len);
}

static CF_STATUS kkdf_xof_expand_wrapper(CF_KDF_CTX *ctx, uint8_t *out, size_t out_len, const CF_KDF_OPTS *opts, bool new_info) {
    UNUSED(opts);
    UNUSED(new_info);
    return ll_KMAC_Final((ll_KMAC_CTX *)ctx->kdf_ctx, out, out_len);
}
static CF_STATUS kkdf_xof_reset_wrapper(CF_KDF_CTX *ctx) {
    return ll_KMAC_Reset((ll_KMAC_CTX *)ctx->kdf_ctx);
}
static CF_STATUS kkdf_xof_clone_ctx_wrapper(CF_KDF_CTX *ctx_dest, const CF_KDF_CTX *ctx_src) {
    return ll_KMAC_CloneCtx((ll_KMAC_CTX *)ctx_dest->kdf_ctx, (const ll_KMAC_CTX *)ctx_src->kdf_ctx);
}

// --- CF_KDF Return Functions ---

//
// HKDF
//

static const CF_KDF *CF_get_hkdf(void) {
    static CF_KDF kdf = {
        .id = CF_HKDF,
        .ctx_size = sizeof(ll_HKDF_CTX),
        .kdf_init_fn = hkdf_init_wrapper,
        .kdf_extract_fn = hkdf_extract_wrapper,
        .kdf_expand_fn = hkdf_expand_wrapper,
        .kdf_reset_fn = hkdf_reset_wrapper,
        .kdf_clone_ctx_fn = hkdf_clone_ctx_wrapper
    };
    return &kdf;
}

static const CF_KDF *CF_get_pbkdf2(void) {
    static CF_KDF kdf = {
        .id = CF_PBKDF2,
        .ctx_size = sizeof(ll_PBKDF2_CTX),
        .kdf_init_fn = pbkdf2_init_wrapper,
        .kdf_extract_fn = pbkdf2_extract_wrapper,
        .kdf_expand_fn = pbkdf2_expand_wrapper,
        .kdf_reset_fn = pbkdf2_reset_wrapper,
        .kdf_clone_ctx_fn = pbkdf2_clone_ctx_wrapper
    };
    return &kdf;
}

static const CF_KDF *CF_get_kkdf_xof(void) {
    static CF_KDF kdf = {
        .id = CF_KMAC_XOF,
        .ctx_size = sizeof(ll_KMAC_CTX),
        .kdf_init_fn = kkdf_xof_init_wrapper,
        .kdf_extract_fn = kkdf_xof_extract_wrapper,
        .kdf_expand_fn = kkdf_xof_expand_wrapper,
        .kdf_reset_fn = kkdf_xof_reset_wrapper,
        .kdf_clone_ctx_fn = kkdf_xof_clone_ctx_wrapper
    };
    return &kdf;
}

// Table of all supported MACs
static const CF_ALGO_ENTRY cf_kdf_table[] = {
    { CF_HKDF,      (const void* (*)(void))CF_get_hkdf     },
    { CF_PBKDF2,    (const void* (*)(void))CF_get_pbkdf2   },
    { CF_KMAC_XOF,  (const void* (*)(void))CF_get_kkdf_xof }
};

const CF_KDF *CF_KDF_GetByFlag(uint32_t algo_flag) {
    if (!CF_IS_KDF(algo_flag)) 
        return NULL;

    size_t table_len = sizeof(cf_kdf_table) / sizeof(cf_kdf_table[0]);
    for (size_t i = 0; i < table_len; i++) {
        if (cf_kdf_table[i].flag == algo_flag) {
            return (const CF_KDF*)cf_kdf_table[i].getter_fn();
        }
    }
    return NULL;
}

CF_STATUS CF_KDF_Init(CF_KDF_CTX *ctx, const CF_KDF *kdf, const CF_KDF_OPTS *opts, uint32_t subflags) {
    if (!ctx || !kdf || !opts)
        return CF_ERR_NULL_PTR;

    if (!CF_IS_KDF(kdf->id))
        return CF_ERR_UNSUPPORTED;

    // CF_KDF_Reset(&ctx);

    ctx->kdf = kdf;
    ctx->opts = opts;
    
    if (CF_KDF_IS_HKDF(ctx->kdf->id) || CF_KDF_IS_PBKDF2(ctx->kdf->id)) {
        // HKDF: requires a hash subflag, cannot have KMAC bits
        if ((subflags & CF_MAC_KMAC_MASK) != 0)
            return CF_ERR_INVALID_PARAM;

        if ((subflags & CF_HASH_MASK) == 0)
            return CF_ERR_INVALID_PARAM; // must specify hash

        if (CF_IS_XOF(subflags))
            return CF_ERR_UNSUPPORTED;

        ctx->md = CF_MD_GetByFlag(subflags);
        if (!ctx->md)
            return CF_ERR_UNSUPPORTED;

    } else if (CF_MAC_IS_KMAC_XOF(ctx->kdf->id)) {
        // KMAC: must have KMAC type, cannot have hash flags
        if ((subflags & CF_MAC_KMAC_MASK) == 0)
            return CF_ERR_INVALID_PARAM;

        // KDF only accepts KMAC-XOF
        if (!CF_IS_KMAC_XOF(subflags))
            return CF_ERR_INVALID_PARAM;

    } else {
        return CF_ERR_INVALID_PARAM;
    }

    // Allocate / initialize KDF internal context
    ctx->kdf_ctx = NULL;

    // Only allocate if context size > 0
    if (ctx->kdf->ctx_size > 0) {
        ctx->kdf_ctx = SECURE_ALLOC(ctx->kdf->ctx_size);
        if (!ctx->kdf_ctx)
            return CF_ERR_ALLOC_FAILED;
    }

    // Initialize context
    CF_STATUS st = ctx->kdf->kdf_init_fn(ctx, ctx->opts);
    if (st != CF_SUCCESS) {
        if (ctx->kdf_ctx)
            SECURE_FREE(ctx->kdf_ctx, ctx->kdf->ctx_size);
        return st;
    }

    return CF_SUCCESS;
}