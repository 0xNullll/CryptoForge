/*
 * CryptoForge - cf_kdf.c / High-level KDF context and utility implementation
 * Copyright (C) 2026 0xNullll
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

#include "../../include/cf_api/cf_kdf.h"


//
// Wrappers for all kdfs
//

// HKDF
static CF_STATUS hkdf_init_wrapper(CF_KDF_CTX *ctx, const CF_KDF_OPTS *opts) {
    return ll_HKDF_Init((ll_HKDF_CTX *)ctx->kdf_ctx, ctx->md, opts->info, opts->info_len);
}

static CF_STATUS hkdf_extract_wrapper(CF_KDF_CTX *ctx, const CF_KDF_OPTS *opts) {
    UNUSED(opts);
    return ll_HKDF_Extract((ll_HKDF_CTX *)ctx->kdf_ctx, ctx->salt, ctx->salt_len, ctx->ikm, ctx->ikm_len);
}

static CF_STATUS hkdf_expand_wrapper(CF_KDF_CTX *ctx, uint8_t *out, size_t out_len, const CF_KDF_OPTS *opts) {
    UNUSED(opts);
    return ll_HKDF_Expand((ll_HKDF_CTX *)ctx->kdf_ctx, out, out_len , opts->info, opts->info_len);
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
    UNUSED(opts);
    return ll_PBKDF2_Extract((ll_PBKDF2_CTX *)ctx->kdf_ctx, ctx->salt, ctx->salt_len);
}

static CF_STATUS pbkdf2_expand_wrapper(CF_KDF_CTX *ctx, uint8_t *out, size_t out_len, const CF_KDF_OPTS *opts) {
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
    return ll_KMAC_Init((ll_KMAC_CTX *)ctx->kdf_ctx, ctx->ikm, ctx->ikm_len, opts->S, opts->S_len, ctx->subflags);
}

static CF_STATUS kkdf_xof_extract_wrapper(CF_KDF_CTX *ctx, const CF_KDF_OPTS *opts) {
    UNUSED(opts);
    return ll_KMAC_Update((ll_KMAC_CTX *)ctx->kdf_ctx, ctx->salt, ctx->salt_len);
}

static CF_STATUS kkdf_xof_expand_wrapper(CF_KDF_CTX *ctx, uint8_t *out, size_t out_len, const CF_KDF_OPTS *opts) {
    UNUSED(opts);
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

// Table of all supported KDFs
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

CF_STATUS CF_KDF_Init(
    CF_KDF_CTX *ctx, const CF_KDF *kdf, const CF_KDF_OPTS *opts,
    const uint8_t *ikm, size_t ikm_len, uint32_t subflags) {
    if (!ctx || !kdf || !ikm)
        return CF_ERR_NULL_PTR;

    // Validate optional context options if provided
    if (opts && opts->magic != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    // Ensure the KDF type is supported
    if (!CF_IS_KDF(kdf->id))
        return CF_ERR_UNSUPPORTED;

    // Check that heap allocation flag is valid (0 or 1)
    if (ctx->isHeapAlloc != 0 && ctx->isHeapAlloc != 1)
        return CF_ERR_CTX_UNINITIALIZED;

    // Reset the context to a clean state before initialization
    CF_KDF_Reset(ctx);

    // Store core parameters in the context
    ctx->kdf      = kdf;
    ctx->opts     = opts;
    ctx->ikm      = ikm;
    ctx->ikm_len  = ikm_len;
    ctx->subflags = subflags;

    // HKDF or PBKDF2 initialization
    if (CF_KDF_IS_HKDF(ctx->kdf->id) || CF_KDF_IS_PBKDF2(ctx->kdf->id)) {

        // These KDFs cannot use KMAC flags
        if ((ctx->subflags & CF_MAC_KMAC_MASK) != 0)
            return CF_ERR_INVALID_PARAM;

        // Require a valid hash flag
        if ((ctx->subflags & CF_HASH_MASK) == 0)
            return CF_ERR_INVALID_PARAM;

        // Extended output functions (XOF) are not supported
        if (CF_IS_XOF(ctx->subflags))
            return CF_ERR_UNSUPPORTED;

        // Retrieve hash function by subflag
        ctx->md = CF_MD_GetByFlag(ctx->subflags);
        if (!ctx->md)
            return CF_ERR_UNSUPPORTED;

    } 
    // KMAC-XOF initialization
    else if (CF_MAC_IS_KMAC_XOF(ctx->kdf->id)) {
        // Must specify a KMAC type
        if ((ctx->subflags & CF_MAC_KMAC_MASK) == 0)
            return CF_ERR_INVALID_PARAM;

        // Must be an XOF variant
        if (!CF_IS_KMAC_XOF(ctx->subflags))
            return CF_ERR_INVALID_PARAM;

    } else {
        // Unsupported KDF type
        return CF_ERR_UNSUPPORTED;
    }

    // Reject contexts with invalid size
    if (ctx->kdf->ctx_size == 0)
        return CF_ERR_CTX_CORRUPT;

    // Allocate memory for KDF internal context
    ctx->kdf_ctx = (void *)SECURE_ALLOC(ctx->kdf->ctx_size);
    if (!ctx->kdf_ctx) {
        // Reset context on allocation failure
        CF_KDF_Reset(ctx);
        return CF_ERR_ALLOC_FAILED;
    }

    // Call the KDF-specific initialization function
    CF_STATUS st = ctx->kdf->kdf_init_fn(ctx, ctx->opts);
    if (st != CF_SUCCESS) {
        // Reset context if initialization fails
        CF_KDF_Reset(ctx);
        return st;
    }

    // Bind magic value for context integrity checking
    // Detects accidental misuse or memory corruption
    ctx->magic = CF_CTX_MAGIC ^ (uintptr_t)ctx->kdf;

    return CF_SUCCESS;
}

 CF_KDF_CTX* CF_KDF_InitAlloc(
    const CF_KDF *kdf, const CF_KDF_OPTS *opts,
    const uint8_t *ikm, size_t ikm_len,
    uint32_t subflags, CF_STATUS *status) {
    if (!kdf) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    // Allocate memory for a new KDF context on the heap
    CF_KDF_CTX *ctx = (CF_KDF_CTX *)SECURE_ALLOC(sizeof(CF_KDF_CTX));
    if (!ctx) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Initialize the newly allocated KDF context
    CF_STATUS st = CF_KDF_Init(ctx, kdf, opts, ikm, ikm_len, subflags);
    if (st != CF_SUCCESS) {
        if (status) *status = st;
        // Clean up on failure
        CF_KDF_Free(&ctx);
        return NULL;
    }

    // Mark context as heap-allocated for proper cleanup later
    ctx->isHeapAlloc = 1;
    
    if (status) *status = CF_SUCCESS;
    return ctx;
}

CF_STATUS CF_KDF_Extract(CF_KDF_CTX *ctx, const uint8_t *salt, size_t salt_len) {
    if (!ctx)
        return CF_ERR_NULL_PTR;

    // Ensure the KDF context and descriptor are initialized
    if (!ctx->kdf || !ctx->kdf_ctx)
        return CF_ERR_CTX_UNINITIALIZED;

    // Verify context integrity using the bound magic value
    // Detects accidental corruption or tampering
    if ((ctx->magic ^ (uintptr_t)ctx->kdf) != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    // Prevent double extraction
    if (ctx->isExtracted)
        return CF_ERR_KDF_ALREADY_EXTRACTED;

    // Store salt and length in the context
    ctx->salt     = salt;
    ctx->salt_len = salt_len;

    // Call the KDF-specific extract function
    CF_STATUS st = ctx->kdf->kdf_extract_fn(ctx, ctx->opts);
    if (st != CF_SUCCESS) {
        // Reset context on failure to avoid partially initialized state
        CF_KDF_Reset(ctx);
        return st;
    }

    // Mark context as extracted
    ctx->isExtracted = 1;

    return CF_SUCCESS;
}


CF_STATUS CF_KDF_Expand(
    CF_KDF_CTX *ctx,
    uint8_t *derived_key, size_t derived_key_len) {
    if (!ctx || !derived_key)
        return CF_ERR_NULL_PTR;

    // Ensure the KDF context and descriptor are initialized
    if (!ctx->kdf || !ctx->kdf_ctx)
        return CF_ERR_CTX_UNINITIALIZED;

    // Validate output length
    if (derived_key_len == 0)
        return CF_ERR_INVALID_LEN;

    // Call the KDF-specific expand function to generate the derived key
    CF_STATUS st = ctx->kdf->kdf_expand_fn(ctx, derived_key, derived_key_len, ctx->opts);
    if (st != CF_SUCCESS) {
        // Reset context on failure to avoid partially derived keys
        CF_KDF_Reset(ctx);
        return st;
    }

    return CF_SUCCESS;
}

CF_STATUS CF_KDF_Reset(CF_KDF_CTX *ctx) {
    if (!ctx)
        return CF_ERR_NULL_PTR;

    // Ensure the KDF descriptor exists
    if (!ctx->kdf)
        return CF_ERR_CTX_UNINITIALIZED;

    // Ensure the KDF type is valid
    if (!CF_IS_KDF(ctx->kdf->id))
        return CF_ERR_UNSUPPORTED;

    CF_STATUS st = CF_SUCCESS;

    // Free the KDF-specific context if it exists
    if (ctx->kdf_ctx) {
        // Call the KDF-specific reset function to clear internal state
        st = ctx->kdf->kdf_reset_fn(ctx);
        if (st != CF_SUCCESS)
            return st;

        // Free allocated memory for the KDF context
        SECURE_FREE(ctx->kdf_ctx, ctx->kdf->ctx_size);
    }

    // Clear all context fields to prevent accidental reuse or leakage
    ctx->kdf         = NULL;
    ctx->md          = NULL;
    ctx->opts        = NULL;
    ctx->ikm         = NULL;
    ctx->salt        = NULL;
    ctx->ikm_len     = 0;
    ctx->salt_len    = 0;
    ctx->subflags    = 0;
    ctx->isExtracted = 0;
    ctx->magic       = 0;

    return st;
}

CF_STATUS CF_KDF_Free(CF_KDF_CTX **p_ctx) {
    if (!p_ctx || !*p_ctx)
        return CF_ERR_NULL_PTR;

    CF_KDF_CTX *ctx = *p_ctx;

    CF_KDF_Reset(ctx);

    if (ctx->isHeapAlloc) {
        SECURE_ZERO(ctx, sizeof(CF_KDF_CTX));
    }

    return CF_SUCCESS;
}

CF_STATUS CF_KDF_Compute(
    const CF_KDF *kdf,
    const uint8_t *ikm, size_t ikm_len,
    const uint8_t *salt, size_t salt_len,
    uint8_t *derived_key, size_t derived_key_len,
    const CF_KDF_OPTS *opts, uint32_t subflags) {
    if (!kdf || !ikm || !derived_key)
        return CF_ERR_NULL_PTR;

    // Output length must be non-zero
    if (derived_key_len == 0)
        return CF_ERR_INVALID_LEN;

    // Stack-allocated KDF context for one-shot derive operation
    CF_KDF_CTX ctx = {0};
    CF_STATUS st = CF_SUCCESS;

    // Initialize KDF context with descriptor, options, IKM, and subflags
    st = CF_KDF_Init(&ctx, kdf, opts, ikm, ikm_len, subflags);

    // Verify initialization success and context integrity
    // Magic check detects accidental corruption or misuse
    if (st != CF_SUCCESS || (ctx.magic ^ (uintptr_t)ctx.kdf) != CF_CTX_MAGIC)
        goto cleanup;

    // Perform extract phase (if applicable for the selected KDF)
    // Salt may be NULL depending on KDF design
    st = CF_KDF_Extract(&ctx, salt, salt_len);

    // Re-verify integrity after extract phase
    if (st != CF_SUCCESS || (ctx.magic ^ (uintptr_t)ctx.kdf) != CF_CTX_MAGIC)
        goto cleanup;

    // Perform expand phase to generate the derived key material
    // Writes derived_key_len bytes into derived_key
    st = CF_KDF_Expand(&ctx, derived_key, derived_key_len);

cleanup:
    // Securely clear context regardless of success or failure
    CF_KDF_Reset(&ctx);

    return st;        
}

const char* CF_KDF_GetName(const CF_KDF *kdf) {
    if (!kdf)
        return NULL;

    switch (kdf->id) {
        case CF_HKDF: return "HKDF";
        case CF_PBKDF2: return "PBKDF2";
        case CF_KMAC_XOF: return "KMAC-XOF";

        default:
            return "UNKNOWN-KDF";
    }
}

const char* CF_KDF_GetFullName(const CF_KDF_CTX *ctx) {
    if (!ctx || !ctx->kdf)
        return NULL;

    switch (ctx->kdf->id) {

    case CF_HKDF:
        switch (ctx->subflags) {
            case CF_SHA1:       return "HKDF-SHA-1";
            case CF_SHA224:     return "HKDF-SHA-224";
            case CF_SHA256:     return "HKDF-SHA-256";
            case CF_SHA384:     return "HKDF-SHA-384";
            case CF_SHA512:     return "HKDF-SHA-512";
            case CF_SHA512_224: return "HKDF-SHA-512/224";
            case CF_SHA512_256: return "HKDF-SHA-512/256";
            case CF_SHA3_224:   return "HKDF-SHA-3/224";
            case CF_SHA3_256:   return "HKDF-SHA-3/256";
            case CF_SHA3_384:   return "HKDF-SHA-3/384";
            case CF_SHA3_512:   return "HKDF-SHA-3/512";
            default:            return "HKDF-UNKNOWN";
        }

    case CF_PBKDF2:
        switch (ctx->subflags) {
            case CF_SHA1:       return "PBKDF2-SHA-1";
            case CF_SHA224:     return "PBKDF2-SHA-224";
            case CF_SHA256:     return "PBKDF2-SHA-256";
            case CF_SHA384:     return "PBKDF2-SHA-384";
            case CF_SHA512:     return "PBKDF2-SHA-512";
            case CF_SHA512_224: return "PBKDF2-SHA-512/224";
            case CF_SHA512_256: return "PBKDF2-SHA-512/256";
            case CF_SHA3_224:   return "PBKDF2-SHA-3/224";
            case CF_SHA3_256:   return "PBKDF2-SHA-3/256";
            case CF_SHA3_384:   return "PBKDF2-SHA-3/384";
            case CF_SHA3_512:   return "PBKDF2-SHA-3/512";
            default:            return "PBKDF2-UNKNOWN";
        }

        case CF_KMAC_XOF:
            switch (ctx->subflags) {
                case CF_KMAC_XOF128:  return "KMAC-XOF-128";
                case CF_KMAC_XOF256:  return "KMAC-XOF-256";
                default:              return "KMAC-UNKNOWN";
            }

        default:
            return "UNKNOWN-KDF";
    }
}

CF_STATUS CF_KDF_ValidateCtx(const CF_KDF_CTX *ctx) {
    if (!ctx)
        return CF_ERR_NULL_PTR;

    // Verify that the KDF pointer hasn’t been tampered with by checking it against the bound magic value.
    if ((ctx->magic ^ (uintptr_t)ctx->kdf) != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    return CF_SUCCESS;
}

CF_STATUS CF_KDF_CloneCtx(CF_KDF_CTX *dst, const CF_KDF_CTX *src) {
    if (!dst || !src)
        return CF_ERR_NULL_PTR;

    if ((src->magic ^ (uintptr_t)src->kdf) != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    // Start with a clean slate
    CF_KDF_Reset(dst);

    // Copy metadata
    dst->magic       = src->magic;
    dst->kdf         = src->kdf;
    dst->md          = src->md;
    dst->opts        = src->opts;
    dst->subflags    = src->subflags;
    dst->isExtracted = src->isExtracted;
    dst->isHeapAlloc = 0;

    // Copy IKM pointer and length (shallow copy)
    dst->ikm     = src->ikm;
    dst->ikm_len = src->ikm_len;

    CF_STATUS st = CF_SUCCESS;

    // Deep copy low-level KDF context
    if (src->kdf_ctx) {
        if (src->kdf->ctx_size == 0)
            return CF_ERR_CTX_CORRUPT;

        dst->kdf_ctx = SECURE_ALLOC(src->kdf->ctx_size);
        if (!dst->kdf_ctx) {
            st = CF_ERR_ALLOC_FAILED;
            goto cleanup;
        }

        st = src->kdf->kdf_clone_ctx_fn(dst, src);
        if (st != CF_SUCCESS)
            goto cleanup;
    }

    return st;

cleanup:
    // Cleanup any partially allocated memory
    if (dst->kdf_ctx && src->kdf->ctx_size)
        SECURE_FREE(dst->kdf_ctx, src->kdf->ctx_size);

    return st;
}

CF_KDF_CTX *CF_KDF_CloneCtxAlloc(const CF_KDF_CTX *src, CF_STATUS *status) {
    if (!src) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    CF_KDF_CTX *dst = (CF_KDF_CTX *)SECURE_ALLOC(sizeof(CF_KDF_CTX));
    if (!dst) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Deep copy contents
    CF_STATUS ret = CF_KDF_CloneCtx(dst, src);
    if (ret != CF_SUCCESS) {
        if (status) *status = ret;
        CF_KDF_Free(&dst);
        return NULL;
    }

    // cloned context is heap-allocated
    dst->isHeapAlloc = 1;

    if (status) *status = CF_SUCCESS;
    return dst;
}

CF_STATUS CF_KDFOpts_Init(
    CF_KDF_OPTS *opts,
    const uint8_t *info, size_t info_len,
    const uint8_t *custom, size_t custom_len,
    uint32_t iterations) {
    if (!opts)
        return CF_ERR_NULL_PTR;

    if ((info && info_len == 0) || (custom && custom_len == 0))
        return CF_ERR_INVALID_PARAM;

    if (custom_len > CF_MAX_CUSTOMIZATION)
        return CF_ERR_INVALID_LEN;

    CF_KDFOpts_Reset(opts);

    opts->info       = info;
    opts->info_len   = info_len;
    opts->S          = custom;
    opts->S_len      = custom_len;
    opts->iterations = iterations;

    opts->magic = CF_CTX_MAGIC;

    return CF_SUCCESS;
}

CF_KDF_OPTS* CF_KDFOpts_InitAlloc(
    const uint8_t *info, size_t info_len,
    const uint8_t *custom, size_t custom_len,
    uint32_t iterations, CF_STATUS *status) {
    if ((info && info_len == 0) || (custom && custom_len == 0)) {
        if (status) *status = CF_ERR_INVALID_PARAM;
        return NULL;
    }

    if (custom_len > CF_MAX_CUSTOMIZATION) {
        if (status) *status = CF_ERR_INVALID_LEN;
        return NULL;
    }

    CF_KDF_OPTS *opts = (CF_KDF_OPTS *)SECURE_ALLOC(sizeof(CF_KDF_OPTS));
    if (!opts) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    CF_STATUS st = CF_KDFOpts_Init(opts, info, info_len, custom, custom_len, iterations);
    if (st != CF_SUCCESS) {
        if (status) *status = st;
        // Clean up on failure
        CF_KDFOpts_Free(&opts);
        return NULL;
    }

    opts->isHeapAlloc = 1;
    if (status) *status = CF_SUCCESS;
    return opts;
}

CF_STATUS CF_KDFOpts_SetNewInfo(CF_KDF_OPTS *opts, const uint8_t *new_info, size_t new_info_len) {
    if (!opts)
        return CF_ERR_NULL_PTR;

    if (new_info && new_info_len == 0)
        return CF_ERR_INVALID_PARAM;

    opts->info = new_info;
    opts->info_len = new_info_len;

    return CF_SUCCESS;
}

CF_STATUS CF_KDFOpts_Reset(CF_KDF_OPTS *opts) {
    if (!opts)
        return CF_ERR_NULL_PTR;

    opts->info       = NULL;
    opts->S          = NULL;
    opts->info_len   = 0;
    opts->S_len      = 0;
    opts->iterations = 0;
    opts->magic      = 0;

    return CF_SUCCESS;
}

CF_STATUS CF_KDFOpts_Free(CF_KDF_OPTS **p_opts) {
    if (!p_opts || !*p_opts)
        return CF_ERR_NULL_PTR;

    CF_KDF_OPTS *opts = *p_opts;

    CF_STATUS ret = CF_KDFOpts_Reset(opts);
    if (ret != CF_SUCCESS)
        return ret;

    if (opts->isHeapAlloc)
        SECURE_FREE(opts, sizeof(*opts));

    return CF_SUCCESS;
}

CF_STATUS CF_KDFOpts_CloneCtx(CF_KDF_OPTS *dst, const CF_KDF_OPTS *src) {
    if (!dst || !src)
        return CF_ERR_NULL_PTR;

    if (src->magic != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    // Start with a clean slate
    CF_KDFOpts_Reset(dst);

    // Shallow copy (caller manages lifetime)
    dst->info      = src->info;
    dst->info_len  = src->info_len;
    dst->S         = src->S;
    dst->S_len     = src->S_len;

    // Copy iteration count (PBKDF2)
    dst->iterations = src->iterations;

    dst->magic       = src->magic;
    dst->isHeapAlloc = 0;

    return CF_SUCCESS;
}

CF_KDF_OPTS* CF_KDFOpts_CloneCtxAlloc(const CF_KDF_OPTS *src, CF_STATUS *status) {
    if (!src) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    CF_KDF_OPTS *dst = (CF_KDF_OPTS *)SECURE_ALLOC(sizeof(CF_KDF_OPTS));
    if (!dst) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Deep copy contents
    CF_STATUS ret = CF_KDFOpts_CloneCtx(dst, src);
    if (ret != CF_SUCCESS) {
        if (status) *status = ret;
        CF_KDFOpts_Free(&dst);
        return NULL;
    }

    // cloned context is heap-allocated
    dst->isHeapAlloc = 1;

    if (status) *status = CF_SUCCESS;
    return dst;
}