/*
 * CryptoForge - gmac.h / GMAC (AES-GMAC) Interface
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

#ifndef GMAC_H
#define GMAC_H

#include "aes_core.h"
#include "gcm_mode.h"
#include "../utils/mem.h"
#include "../utils/cf_status.h"
#include "../config/libs.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================
// GMAC context structure
// ============================
typedef struct _ll_GMAC_CTX {
    const ll_AES_KEY *key;             // AES key
    uint8_t H[AES_BLOCK_SIZE];      // Hash subkey
    uint8_t J0[AES_BLOCK_SIZE];     // Initial counter block
    uint8_t X[AES_BLOCK_SIZE];      // GHASH accumulator
    size_t aad_len;                 // Length of AAD processed

    int isFinalized;
    int isHeapAlloc;
} ll_GMAC_CTX;

// ============================
// GMAC low-level function prototypes
// ============================

// Initialize a GMAC context with AES key and IV
CF_STATUS ll_GMAC_Init(ll_GMAC_CTX *ctx, const ll_AES_KEY *key, const uint8_t *iv, size_t iv_len);

// Allocates and initialize a GMAC context with AES key and IV
ll_GMAC_CTX* ll_GMAC_InitAlloc(const ll_AES_KEY *key, const uint8_t *iv, size_t iv_len, CF_STATUS *status);

// Update GMAC with Additional Authenticated Data (AAD)
CF_STATUS ll_GMAC_Update(ll_GMAC_CTX *ctx, const uint8_t *aad, size_t aad_len);

// Finalize GMAC and output tag
CF_STATUS ll_GMAC_Final(ll_GMAC_CTX *ctx, uint8_t *tag, size_t tag_len);

// Verify a computed GMAC tag against an expected tag
CF_STATUS ll_GMAC_Verify(
    const ll_AES_KEY *key,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *expected_tag, size_t tag_len);

// Free internal buffers of a pre-allocated GMAC context
CF_STATUS ll_GMAC_Reset(ll_GMAC_CTX *ctx);

// Free internal buffers + heap-allocated GMAC context
CF_STATUS ll_GMAC_Free(ll_GMAC_CTX **p_ctx);

// Clone a GMAC context into an existing destination
CF_STATUS ll_GMAC_CloneCtx(ll_GMAC_CTX *ctx_dest, const ll_GMAC_CTX *ctx_src);

// Clone and allocate a new heap GMAC context
ll_GMAC_CTX* ll_GMAC_CloneCtxAlloc(const ll_GMAC_CTX *ctx_src, CF_STATUS *status);

#ifdef __cplusplus
}
#endif

#endif // GMAC_H