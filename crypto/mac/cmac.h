/*
 * CryptoForge - cmac.h / CMAC (AES-CMAC) Interface
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

#ifndef CMAC_H
#define CMAC_H

#include "../cipher/aes/aes_core.h"
#include "../../utils/mem.h"
#include "../../utils/cf_status.h"
#include "../../config/libs.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================
// CMAC context structure
// ============================
typedef struct _ll_CMAC_CTX {
    const AES_KEY *key;      // AES key
    uint8_t K1[16];          // Subkey 1
    uint8_t K2[16];          // Subkey 2
    uint8_t X[16];           // Current MAC state
    size_t msg_len;          // Total message length processed
    int phase;               // Current processing phase

    int isHeapAlloc;         // Tracks if context was heap allocated
} ll_CMAC_CTX;

typedef enum {
    CMAC_PHASE_INIT,         // just initialized, nothing processed
    CMAC_PHASE_UPDATE,       // processing message
    CMAC_PHASE_FINAL         // finalize has been called
} ll_CMAC_PHASE;

// ============================
// CMAC low-level function prototypes
// ============================

// Initialize a CMAC context with AES key
CF_STATUS ll_CMAC_Init(ll_CMAC_CTX *ctx, const AES_KEY *key);

// Update CMAC with message data
CF_STATUS ll_CMAC_Update(ll_CMAC_CTX *ctx, const uint8_t *data, size_t data_len);

// Finalize CMAC and output tag
CF_STATUS ll_CMAC_Final(ll_CMAC_CTX *ctx, uint8_t *tag, size_t tag_len);

// Free internal buffers of a pre-allocated CMAC context
CF_STATUS ll_CMAC_Free(ll_CMAC_CTX *ctx);

// Free internal buffers + heap-allocated CMAC context
CF_STATUS ll_CMAC_FreeAlloc(ll_CMAC_CTX **p_ctx);

// Verify a computed CMAC tag against an expected tag
CF_STATUS ll_CMAC_Verify(const ll_CMAC_CTX *ctx, const uint8_t *expected_tag, size_t tag_len);

// Clone a CMAC context into an existing destination
CF_STATUS ll_CMAC_CloneCtx(ll_CMAC_CTX *ctx_dest, const ll_CMAC_CTX *ctx_src);

// Clone and allocate a new heap CMAC context
ll_CMAC_CTX* ll_CMAC_CloneCtxAlloc(const ll_CMAC_CTX *ctx_src, CF_STATUS *status);

#ifdef __cplusplus
}
#endif

#endif // CMAC_H