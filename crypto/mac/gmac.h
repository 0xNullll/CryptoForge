/*
 * CryptoForge - gmac.h / GMAC (AES-GMAC) Interface
 * Copyright (C) 2026 0xNullll
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

#ifndef GMAC_H
#define GMAC_H

#include "../cipher/aes/aes_core.h"
#include "../cipher/aes/gcm_mode.h"
#include "../../utils/mem.h"
#include "../../utils/cf_status.h"
#include "../../config/libs.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================
// GMAC context structure
// ============================
typedef struct _ll_GMAC_CTX {
    const AES_KEY *key;      // AES key
    uint8_t H[16];           // Hash subkey
    uint8_t J0[16];          // Initial counter block
    uint8_t X[16];           // GHASH accumulator
    size_t aad_len;          // Length of AAD processed
    int phase;               // Current processing phase

    int isHeapAlloc;
} ll_GMAC_CTX;

typedef enum {
    GMAC_PHASE_INIT,     // just initialized, nothing processed
    GMAC_PHASE_AAD,      // processing AAD
    GMAC_PHASE_DATA,     // processing ciphertext/data
    GMAC_PHASE_FINAL     // finalize has been called
} ll_GMAC_PHASE;

// ============================
// GMAC low-level function prototypes
// ============================

// Initialize a GMAC context with AES key and IV
CF_STATUS ll_GMAC_Init(ll_GMAC_CTX *ctx, const AES_KEY *key, const uint8_t *iv, size_t iv_len);

// Update GMAC with Additional Authenticated Data (AAD)
CF_STATUS ll_GMAC_Update(ll_GMAC_CTX *ctx, const uint8_t *aad, size_t aad_len);

// Finalize GMAC and output tag
CF_STATUS ll_GMAC_Final(ll_GMAC_CTX *ctx, uint8_t *tag, size_t tag_len);

// Free internal buffers of a pre-allocated GMAC context
CF_STATUS ll_GMAC_Free(ll_GMAC_CTX *ctx);

// Free internal buffers + heap-allocated GMAC context
CF_STATUS ll_GMAC_FreeAlloc(ll_GMAC_CTX **p_ctx);

// Verify a computed GMAC tag against an expected tag
CF_STATUS ll_GMAC_Verify(const ll_GMAC_CTX *ctx, const uint8_t *expected_tag, size_t tag_len);

// Clone a GMAC context into an existing destination
CF_STATUS ll_GMAC_CloneCtx(ll_GMAC_CTX *ctx_dest, const ll_GMAC_CTX *ctx_src);

// Clone and allocate a new heap GMAC context
ll_GMAC_CTX* ll_GMAC_CloneCtxAlloc(const ll_GMAC_CTX *ctx_src, CF_STATUS *status);

#ifdef __cplusplus
}
#endif

#endif // GMAC_H