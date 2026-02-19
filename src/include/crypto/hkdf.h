/*
 * CryptoForge - hkdf.h / HKDF (HKDF-HMAC-SHA1, SHA2, SHA3) Interface
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

#ifndef HKDF_H
#define HKDF_H

#include "hmac.h"

#include "../cf_api/cf_hash.h"
#include "../cf_api/cf_defs.h"
#include "../cf_api/cf_flags.h"

#include "../utils/mem.h"
#include "../utils/cf_status.h"

#include "../config/libs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LL_HKDF_MAX_BLOCKS 255  // Maximum number of HKDF-Expand blocks (per RFC 5869)

#define LL_HKDF_MAX_OKM(hash_len) ((size_t)(LL_HKDF_MAX_BLOCKS) * (size_t)(hash_len))

// ============================
// HKDF context structure
// ============================
typedef struct _ll_HKDF_CTX {
    const CF_HASH *hash;         // Low-level hash descriptor

    uint8_t *prk;             // Pseudorandom key from Extract (constant HMAC key)
    size_t prk_len;           // Length of PRK (HashLen)

    uint8_t prev_block[CF_MAX_DEFAULT_DIGEST_SIZE];  // Last HMAC output (Ti), max hash size
    uint8_t counter;                                 // Block counter (1..255)

    const uint8_t *info;             // Optional context info
    size_t info_len;           // Length of info

    int isExtracted;
    int isHeapAlloc;           // 1 if allocated by library (heap), 0 if user stack
} ll_HKDF_CTX;

// ============================
// HKDF low-level function prototypes
// ============================

// Initializes a new HKDF_CTX with optional info; PRK is not set yet.
CF_STATUS ll_HKDF_Init(ll_HKDF_CTX *ctx, const CF_HASH *hash, const uint8_t *info, size_t info_len);

// Allocates and initializes a new HKDF_CTX on the heap
ll_HKDF_CTX* ll_HKDF_InitAlloc(const CF_HASH *hash, const uint8_t *info, size_t info_len, CF_STATUS *status);

// Performs HKDF-Extract with given salt and input key material, stores PRK in context
CF_STATUS ll_HKDF_Extract(
    ll_HKDF_CTX *ctx,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *ikm, size_t ikm_len);

// Performs HKDF-Expand using the stored PRK and info, writes OKM of okm_len bytes
CF_STATUS ll_HKDF_Expand(
    ll_HKDF_CTX *ctx,
    uint8_t *okm, size_t okm_len,
    const uint8_t *new_info, size_t new_info_len);

// Frees internal buffers of a pre-allocated context
CF_STATUS ll_HKDF_Reset(ll_HKDF_CTX *ctx);

// Frees internal buffers + the heap-allocated context
CF_STATUS ll_HKDF_Free(ll_HKDF_CTX **p_ctx);

// Clone HKDF context into an existing destination context
CF_STATUS ll_HKDF_CloneCtx(ll_HKDF_CTX *ctx_dest, const ll_HKDF_CTX *ctx_src);

// Clone HKDF context and allocate a new heap context
ll_HKDF_CTX *ll_HKDF_CloneCtxAlloc(const ll_HKDF_CTX *ctx_src, CF_STATUS *status);

#ifdef __cplusplus
}
#endif

#endif // HKDF_H