/*
 * CryptoForge - cf_mac.h / High-level MAC context and utility definitions
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against WyChaProof test vectors. No hardware optimizations. Use with caution.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#ifndef CF_MAC_H
#define CF_MAC_H

#include "../config/crypto_config.h"
#include "../config/libs.h"

#include "../utils/misc.h"
#include "../utils/mem.h"
#include "../utils/cf_status.h"

#include "cf_defs.h"
#include "cf_flags.h"

#include "../crypto/hmac.h"
#include "../crypto/kmac.h"
#include "../crypto/cmac.h"
#include "../crypto/gmac.h"
#include "../crypto/poly1305.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================
// MAC descriptor
// ============================
typedef struct _CF_MAC {
    uint32_t id;                  // CF MAC ID / flag
    size_t ctx_size;              // low-level context size
    size_t key_ctx_size;          // low-level cipher key context size
    size_t default_tag_len;

    // Low-level function pointers
    CF_STATUS (*mac_init_fn)(struct _CF_MAC_CTX *ctx, const struct _CF_MAC_OPTS *opts);
    CF_STATUS (*mac_update_fn)(struct _CF_MAC_CTX *ctx, const uint8_t *data, size_t data_len);
    CF_STATUS (*mac_final_fn)(struct _CF_MAC_CTX *ctx, uint8_t *tag, size_t tag_len);
    CF_STATUS (*mac_reset_fn)(struct _CF_MAC_CTX *ctx);
    CF_STATUS (*mac_verify_fn)(struct _CF_MAC_CTX *ctx,
                            const uint8_t *data, size_t data_len,
                            const uint8_t *expected_tag, size_t expected_tag_len,
                            const struct _CF_MAC_OPTS *opts);
    CF_STATUS (*mac_clone_ctx_fn)(struct _CF_MAC_CTX *ctx_dest, const struct _CF_MAC_CTX *ctx_src);
} CF_MAC;

// ============================
// Optional MAC parameters
// ============================
typedef struct _CF_MAC_OPTS {
    uint32_t magic;             //  CF_CTX_MAGIC

    uint8_t iv[AES_BLOCK_SIZE]; // optional IV for GMAC
    size_t iv_len;

    const uint8_t *S;           // optional customization for KMAC
    size_t S_len;

    int isHeapAlloc;
} CF_MAC_OPTS;

// ============================
// MAC context
// ============================
typedef struct _CF_MAC_CTX {
    uint64_t magic;               // CF_CTX_MAGIC ^ (uintptr_t)mac

    const CF_MAC *mac;            // selected MAC algorithm
    const CF_MD *md;              // mandetory for HMAC
    const CF_MAC_OPTS *opts;      // optional parameters

    void *key_ctx;                // optional low-level key for CMAC/GMAC

    void *mac_ctx;                // low-level MAC context (internal)
    const uint8_t *key;           // user-supplied key bits
    size_t key_len;               // length of key in bytes
    size_t tag_len;               // requested tag length
    uint32_t subflags;            // algorithm-specific subflags
    int isFinalized;
    int isHeapAlloc;
} CF_MAC_CTX;

// ============================
// Algorithm selection
// ============================
CF_API const CF_MAC *CF_MAC_GetByFlag(uint32_t mac_flag);

// ============================
// Context initialization & cleanup
// ============================
CF_API CF_STATUS CF_MAC_Init(CF_MAC_CTX *ctx, const CF_MAC *mac, const CF_MAC_OPTS *opts,
                             const uint8_t *key, size_t key_len, uint32_t subflags);

CF_API CF_MAC_CTX* CF_MAC_InitAlloc(const CF_MAC *mac, const CF_MAC_OPTS *opts,
                                    const uint8_t *key, size_t key_len, uint32_t subflags,
                                    CF_STATUS *status);

CF_API CF_STATUS CF_MAC_Update(CF_MAC_CTX *ctx, const uint8_t *data, size_t data_len);
CF_API CF_STATUS CF_MAC_Final(CF_MAC_CTX *ctx, uint8_t *tag, size_t tag_len);

CF_API CF_STATUS CF_MAC_Reset(CF_MAC_CTX *ctx);
CF_API CF_STATUS CF_MAC_Free(CF_MAC_CTX **p_ctx);

// Verifies a MAC tag against expected output.
CF_API CF_STATUS CF_MAC_Verify(const CF_MAC *mac,
                               const uint8_t *key, size_t key_len,
                               const uint8_t *data, size_t data_len,
                               const uint8_t *expected_mac, size_t expected_mac_len,
                               const CF_MAC_OPTS *opts, uint32_t subflags);

// ============================
// One-shot MAC computation
// ============================
CF_API CF_STATUS CF_MAC_Compute(const CF_MAC *mac,
                                const uint8_t *key, size_t key_len,
                                const uint8_t *data, size_t data_len,
                                uint8_t *tag, size_t tag_len,
                                const CF_MAC_OPTS *opts, uint32_t subflags);


CF_API const char* CF_MAC_GetName(const CF_MAC *ctx);
CF_API const char* CF_MAC_GetFullName(const CF_MAC_CTX *ctx);
CF_API CF_STATUS CF_MAC_ValidateCtx(const CF_MAC_CTX *ctx);

// ============================
// Cloning
// ============================
CF_API CF_STATUS CF_MAC_CloneCtx(CF_MAC_CTX *dst, const CF_MAC_CTX *src);
CF_API CF_MAC_CTX* CF_MAC_CloneCtxAlloc(const CF_MAC_CTX *src, CF_STATUS *status);

// ============================
// Optional parameters init / cleanup
// ============================
CF_API CF_STATUS CF_MACOpts_Init(CF_MAC_OPTS *opts,
                                 const uint8_t *iv, size_t iv_len,
                                 const uint8_t *custom, size_t custom_len);

CF_API CF_MAC_OPTS* CF_MACOpts_InitAlloc(const uint8_t *iv, size_t iv_len,
                                         const uint8_t *custom, size_t custom_len,
                                         CF_STATUS *status);

CF_API CF_STATUS CF_MACOpts_Reset(CF_MAC_OPTS *opts);
CF_API CF_STATUS CF_MACOpts_Free(CF_MAC_OPTS **p_opts);

CF_API CF_STATUS CF_MACOpts_CloneCtx(CF_MAC_OPTS *dst, const CF_MAC_OPTS *src);
CF_API CF_MAC_OPTS* CF_MACOpts_CloneCtxAlloc(const CF_MAC_OPTS *src, CF_STATUS *status);

#ifdef __cplusplus
}
#endif

#endif // CF_MAC_H