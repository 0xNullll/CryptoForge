/*
 * CryptoForge - hkdf.h / HKDF (HKDF-SHA-1, HKDF-SHA-2, and HKDF-SHA-3) Interface
 * Copyright (C) 2025 0xNullll
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the MIT License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * You should have received a copy of the MIT License along with this program.
 * If not, see <https://opensource.org/licenses/MIT>.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#ifndef HKDF_H
#define HKDF_H

#include "../mac/hmac.h"

#include "../evp/evp_hash.h"
#include "../evp/evp_defs.h"
#include "../evp/evp_flags.h"

#include "../../utils/mem.h"
#include "../../utils/CF_status.h"

#include "../../config/libs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LL_HKDF_MAX_BLOCKS 255  // Maximum number of HKDF-Expand blocks (per RFC 5869)

#define LL_HKDF_MAX_OKM(hash_len) ((size_t)(LL_HKDF_MAX_BLOCKS) * (size_t)(hash_len))

// ============================
// HKDF context structure
// ============================
typedef struct _ll_HKDF_CTX {
    const EVP_MD *md;         // Low-level hash descriptor

    uint8_t *prk;             // Pseudorandom key from Extract (constant HMAC key)
    size_t prk_len;           // Length of PRK (HashLen)

    uint8_t prev_block[EVP_MAX_DEFAULT_DIGEST_SIZE]; // Last HMAC output (Ti), max hash size
    uint8_t counter;                                 // Block counter (1..255)

    uint8_t *info;             // Optional context info
    size_t info_len;           // Length of info

    int isHeapAlloc;           // 1 if allocated by library (heap), 0 if user stack
} ll_HKDF_CTX;

// ============================
// HKDF low-level function prototypes
// ============================

// Initializes a new HKDF_CTX with optional info; PRK is not set yet.
CF_STATUS ll_HKDF_Init(ll_HKDF_CTX *ctx, const EVP_MD *md, const uint8_t *info, size_t info_len);

// Allocates and initializes a new HKDF_CTX on the heap
ll_HKDF_CTX* ll_HKDF_InitAlloc(const EVP_MD *md, const uint8_t *info, size_t info_len, CF_STATUS *status);

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
CF_STATUS ll_HKDF_Free(ll_HKDF_CTX *ctx);

// Frees internal buffers + the heap-allocated context
CF_STATUS ll_HKDF_FreeAlloc(ll_HKDF_CTX **p_ctx);

// Clone HKDF context into an existing destination context
CF_STATUS ll_HKDF_CloneCtx(ll_HKDF_CTX *ctx_dest, const ll_HKDF_CTX *ctx_src);

// Clone HKDF context and allocate a new heap context
ll_HKDF_CTX *ll_HKDF_CloneCtxAlloc(const ll_HKDF_CTX *ctx_src, CF_STATUS *status);

#ifdef __cplusplus
}
#endif

#endif // HKDF_H