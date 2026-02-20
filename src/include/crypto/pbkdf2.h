/*
 * CryptoForge - pbkdf2.h / PBKDF2 (PBKDF2-HMAC-SHA1, SHA2, SHA3) Interface
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
#ifndef PBKDF2_H
#define PBKDF2_H

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

#define LL_PBKDF2_MIN_ITERATIONS 1000
#define LL_PBKDF2_MAX_ITERATION 0xFFFFFFFF
#define LL_PBKDF2_MAX_DKLEN  (1024*1024) // Arbitrary max derived key length

// ============================
// PBKDF2 context structure
// ============================
typedef struct _ll_PBKDF2_CTX {
    const CF_HASH *hash;          // Low-level hash descriptor

    const uint8_t *password;  // Password bytes
    size_t password_len;       

    uint8_t *salt;         // salt bytes
    size_t salt_len;       

    size_t iterations;         // Iteration count
    size_t dk_len;             // Desired output length

    uint8_t prev_block[CF_MAX_DEFAULT_DIGEST_SIZE];  // Last block Ti
    uint32_t block_index;                             // Block counter (1..N)
    size_t generated_len;                             // Total DK bytes generated

    int isExtracted;
    int isHeapAlloc;          // 1 if allocated by library (heap), 0 if user stack
} ll_PBKDF2_CTX;

// ============================
// PBKDF2 low-level function prototypes
// ============================

// Initialize PBKDF2 context with password; salt not set yet
CF_STATUS ll_PBKDF2_Init(
    ll_PBKDF2_CTX *ctx,
    const CF_HASH *hash,
    const uint8_t *password, size_t password_len);

// Allocate and initialize a PBKDF2 context on the heap
ll_PBKDF2_CTX* ll_PBKDF2_InitAlloc(
    const CF_HASH *hash,
    const uint8_t *password, size_t password_len,
    CF_STATUS *status);

// Performs PBKDF2-Extract: sets salt and prepares PRF
CF_STATUS ll_PBKDF2_Extract(
    ll_PBKDF2_CTX *ctx,
    const uint8_t *salt, size_t salt_len);

// Performs PBKDF2-Expand: runs iterations and produces the derived key
CF_STATUS ll_PBKDF2_Expand(
    ll_PBKDF2_CTX *ctx,
    uint8_t *dk, size_t dk_len,
    const size_t iterations);

// Frees internal buffers of a pre-allocated context
CF_STATUS ll_PBKDF2_Reset(ll_PBKDF2_CTX *ctx);

// Frees internal buffers + heap-allocated context
CF_STATUS ll_PBKDF2_Free(ll_PBKDF2_CTX **p_ctx);

// Clone PBKDF2 context into an existing destination context
CF_STATUS ll_PBKDF2_CloneCtx(ll_PBKDF2_CTX *ctx_dest, const ll_PBKDF2_CTX *ctx_src);

// Clone PBKDF2 context and allocate a new heap context
ll_PBKDF2_CTX *ll_PBKDF2_CloneCtxAlloc(const ll_PBKDF2_CTX *ctx_src, CF_STATUS *status);

// Compute recommended PBKDF2 iterations based on hash size (in bytes)
uint32_t ll_PBKDF2_RecommendedIterations(const ll_PBKDF2_CTX *ctx);

#ifdef __cplusplus
}
#endif

#endif // PBKDF2_H