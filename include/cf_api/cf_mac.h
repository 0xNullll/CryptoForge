/*
 * CryptoForge - cf_mac.h / High-level MAC context and utility definitions
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

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _CF_MAC {
    uint32_t id;                  // CF MAC ID / flag
    size_t tag_size;              // default output length
    size_t block_size;
    size_t ctx_size;              // low-level context size
    size_t opts_ctx_size;         // optional context size (CF_MAC_OPTS)
    size_t default_out_len;

    // Low-level function pointers

    // Initializes the full low-level MAC context using the given CF_MAC_CTX and options.
    // Allocates any internal substructures if needed and can access the key via ctx.
    void*     (*mac_init_alloc_fn)(CF_MAC_CTX *ctx, const CF_MAC_OPTS *opts, CF_STATUS *status);

    // Processes input data on the low-level context.
    CF_STATUS (*mac_update_fn)(CF_MAC_CTX *ctx, const uint8_t *data, size_t data_len);

    // Finalizes the MAC computation and writes the tag.
    CF_STATUS (*mac_final_fn)(CF_MAC_CTX *ctx, uint8_t *tag, size_t tag_len);

    // Frees any memory allocated internally by mac_init_alloc_fn.
    CF_STATUS (*mac_free_fn)(CF_MAC_CTX *ctx);
} CF_MAC;

typedef struct _CF_MAC_OPTS {
    const struct _CF_MD *md;     // mandetory for HMAC
    const void *cipher_key;      // optional low-level key for CMAC/GMAC
    size_t cipher_key_len;

    const uint8_t *iv;           // optional IV (GMAC or other MACs)
    size_t iv_len;

    uint8_t custom[CF_MAX_CUSTOMIZATION]; // optional custom bytes
    size_t custom_len;

    int isHeapAlloc;              // 1 if allocated by library, 0 if user stack
} CF_MAC_OPTS;

typedef struct _CF_MAC_CTX {
    const struct _CF_MAC *mac;   // selected MAC algorithm
    const void *opts;             // pointer to CF_MAC_OPTS or NULL
    void *mac_ctx;                // low-level MAC context
    const uint8_t *key;           // user-supplied key
    size_t key_len;               // length of key
    size_t tag_len;               // Requested output length in bytes (Mandetory for KMAC)
    uint32_t subflags;            // e.g., KMAC type, XOF choice, etc.
    int isFinalized;
    int isHeapAlloc;
} CF_MAC_CTX;

//
// Algorithm selection
//
CF_API const CF_MAC *CF_MACByFlag(uint32_t mac_flag);

//
// High-level MAC init / cleanup
//
CF_API CF_STATUS CF_MACInit(CF_MAC_CTX *ctx, const CF_MAC *mac, const CF_MAC_OPTS *opts,
                            const uint8_t *key, size_t key_len);

CF_API CF_MAC_CTX* CF_MACInitAlloc(const CF_MAC *mac, const CF_MAC_OPTS *opts,
                                   const uint8_t *key, size_t key_len,
                                   CF_STATUS *status);

CF_API CF_STATUS CF_MACUpdate(CF_MAC_CTX *ctx, const uint8_t *data, size_t data_len);
CF_API CF_STATUS CF_MACFinal(CF_MAC_CTX *ctx, uint8_t *tag, size_t tag_len);

CF_API CF_STATUS CF_MACFree(CF_MAC_CTX *ctx);
CF_API CF_STATUS CF_MACFreeAlloc(CF_MAC_CTX **p_ctx);

//
// One-shot MAC convenience
//
CF_API CF_STATUS CF_MACCompute(
    const CF_MAC        *mac,
    const uint8_t       *key,
    size_t               key_len,
    const uint8_t       *data,
    size_t               data_len,
    uint8_t             *tag,
    size_t               tag_len,
    const CF_MAC_OPTS   *opts       // optional
);

//
// Utility / cloning
//
CF_API CF_STATUS CF_CloneMACCtx(CF_MAC_CTX *dst, const CF_MAC_CTX *src);
CF_API CF_MAC_CTX* CF_CloneMACCtxAlloc(const CF_MAC_CTX *src, CF_STATUS *status);

//
// Extra opts init / cleanup
//
CF_API CF_STATUS CF_MACOptsInit(
    CF_MAC_OPTS *opts,
    const void *cipher_key, size_t cipher_key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *custom, size_t custom_len
);

CF_API CF_MAC_OPTS* CF_MACOptsInitAlloc(
    const void *cipher_key, size_t cipher_key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *custom, size_t custom_len,
    CF_STATUS *status
);

CF_API void CF_MACOptsFree(CF_MAC_OPTS *opts);
CF_API void CF_MACOptsFreeAlloc(CF_MAC_OPTS **p_opts);

#ifdef __cplusplus
}
#endif

#endif // CF_MAC_H