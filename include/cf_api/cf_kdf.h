/*
 * CryptoForge - cf_kdf.h / High-level KDF context and utility definitions
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against WyChaProof test vectors. No hardware optimizations. Use with caution.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#ifndef CF_KDF_H
#define CF_KDF_H

#include "../config/crypto_config.h"
#include "../config/libs.h"

#include "../utils/misc.h"
#include "../utils/mem.h"
#include "../utils/cf_status.h"

#include "cf_defs.h"
#include "cf_flags.h"

#include "../crypto/hkdf.h"
#include "../crypto/pbkdf2.h"
#include "../crypto/kmac.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================
// KDF descriptor
// ============================
typedef struct _CF_KDF {
    uint32_t id;
    size_t ctx_size;

    CF_STATUS (*kdf_init_fn)(struct _CF_KDF_CTX *ctx, const struct _CF_KDF_OPTS *opts);
    
    CF_STATUS (*kdf_extract_fn)(struct _CF_KDF_CTX *ctx, const struct _CF_KDF_OPTS *opts);
    
    CF_STATUS (*kdf_expand_fn)(struct _CF_KDF_CTX *ctx, uint8_t *out, size_t out_len, const struct _CF_KDF_OPTS *opts);
    
    CF_STATUS (*kdf_reset_fn)(struct _CF_KDF_CTX *ctx);

    CF_STATUS (*kdf_clone_ctx_fn)(struct _CF_KDF_CTX *ctx_dest, const struct _CF_KDF_CTX *ctx_src);
} CF_KDF;

// ============================
// Optional KDF parameters
// ============================
typedef struct _CF_KDF_OPTS {
    uint32_t magic;               // CF_CTX_MAGIC

    const uint8_t *info;          // optional salt (HKDF)
    size_t info_len;

    uint32_t iterations;          // iteration count (PBKDF2)

    uint8_t S[CF_MAX_CUSTOMIZATION]; // optional customization (KMAC-XOF)
    size_t S_len;

    int isHeapAlloc;
} CF_KDF_OPTS;

// ============================
// KDF context
// ============================
typedef struct _CF_KDF_CTX {
    uint64_t magic;         // CF_CTX_MAGIC ^ (uintptr_t)kdf

    const CF_KDF *kdf;
    const CF_MD *md;
    const CF_KDF_OPTS *opts;

    void *kdf_ctx;

    const uint8_t *ikm;
    size_t ikm_len;

    const uint8_t *salt;          // optional salt (HKDF/PBKDF2/KMAC-XOF)
    size_t salt_len;

    uint32_t subflags;
    int isExtracted;
    int isHeapAlloc;
} CF_KDF_CTX;

// ============================
// Algorithm selection
// ============================
CF_API const CF_KDF *CF_KDF_GetByFlag(uint32_t kdf_flag);

// ============================
// Context initialization & cleanup
// ============================
CF_API CF_STATUS CF_KDF_Init(
    CF_KDF_CTX *ctx,
    const CF_KDF *kdf,
    const uint8_t *ikm, size_t ikm_len,
    const CF_KDF_OPTS *opts,
    uint32_t subflags
);

CF_API CF_KDF_CTX* CF_KDF_InitAlloc(
    const CF_KDF *kdf,
    const CF_KDF_OPTS *opts,
    const uint8_t *ikm, size_t ikm_len,
    uint32_t subflags,
    CF_STATUS *status
);

CF_API CF_STATUS CF_KDF_Extract(
    CF_KDF_CTX *ctx,
    const uint8_t *salt, size_t salt_len // salt/data
);

CF_API CF_STATUS CF_KDF_Expand(
    CF_KDF_CTX *ctx,
    uint8_t *derived_key, size_t derived_key_len
);

CF_API CF_STATUS CF_KDF_Reset(CF_KDF_CTX *ctx);
CF_API CF_STATUS CF_KDF_Free(CF_KDF_CTX **p_ctx);

// ============================
// One-shot KDF computation
// ============================
CF_API CF_STATUS CF_KDF_Compute(const CF_KDF *kdf,
                                const uint8_t *ikm, size_t ikm_len,
                                const uint8_t *salt, size_t salt_len,
                                uint8_t *derived_key, size_t derived_key_len,
                                const CF_KDF_OPTS *opts, uint32_t subflags);

CF_API const char* CF_KDF_GetName(const CF_KDF *kdf);
CF_API const char* CF_KDF_GetFullName(const CF_KDF_CTX *ctx);
CF_API CF_STATUS CF_KDF_IsValid(const CF_KDF_CTX *ctx);

// ============================
// Cloning
// ============================
CF_API CF_STATUS CF_KDF_CloneCtx(CF_KDF_CTX *dst, const CF_KDF_CTX *src);
CF_API CF_KDF_CTX* CF_KDF_CloneCtxAlloc(const CF_KDF_CTX *src, CF_STATUS *status);

// ============================
// Optional parameters init / cleanup
// ============================
CF_API CF_STATUS CF_KDFOpts_Init(CF_KDF_OPTS *opts,
                                 const uint8_t *info, size_t info_len,
                                 const uint8_t *custom, size_t custom_len,
                                 uint32_t iterations);

CF_API CF_KDF_OPTS* CF_KDFOpts_InitAlloc(const uint8_t *info, size_t info_len,
                                         const uint8_t *custom, size_t custom_len,
                                         uint32_t iterations, CF_STATUS *status);

CF_API CF_STATUS CF_KDFOpts_SetNewInfo(CF_KDF_OPTS *opts, const uint8_t *new_info, size_t new_info_len);

CF_API CF_STATUS CF_KDFOpts_Reset(CF_KDF_OPTS *opts);
CF_API CF_STATUS CF_KDFOpts_Free(CF_KDF_OPTS **p_opts);

CF_API CF_STATUS CF_KDFOpts_CloneCtx(CF_KDF_OPTS *dst, const CF_KDF_OPTS *src);
CF_API CF_KDF_OPTS* CF_KDFOpts_CloneCtxAlloc(const CF_KDF_OPTS *src, CF_STATUS *status);

#ifdef __cplusplus
}
#endif

#endif // CF_KDF_H