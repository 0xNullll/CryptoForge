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

#include "../../utils/mem.h"
#include "../../utils/cf_status.h"
#include "../../config/libs.h"

#include "../cipher/aes/aes_core.h"
#include "../cipher/aes/aes_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LL_CMAC_TAG_LEN_AES_BLOCK 16   // AES block = 128 bits → CMAC tag 16 bytes

// ============================
// CMAC context structure
// ============================
typedef struct _ll_CMAC_CTX {
    const ll_AES_KEY *key;       // AES key

    uint8_t unprocessed_block[AES_BLOCK_SIZE];
    size_t unprocessed_len; // how many bytes currently in it
    uint8_t last_block[AES_BLOCK_SIZE];  // XORed block state

    int isFinalized;
    int isHeapAlloc;
} ll_CMAC_CTX;

// ============================
// CMAC low-level function prototypes
// ============================

// Initialize a CMAC context with AES key
CF_STATUS ll_CMAC_Init(ll_CMAC_CTX *ctx, const ll_AES_KEY *key);

// Update CMAC with message data
CF_STATUS ll_CMAC_Update(ll_CMAC_CTX *ctx, const uint8_t *data, size_t data_len);

// Finalize CMAC and output tag
CF_STATUS ll_CMAC_Final(ll_CMAC_CTX *ctx, uint8_t *tag, size_t tag_len);

// Free internal buffers of a pre-allocated CMAC context
CF_STATUS ll_CMAC_Free(ll_CMAC_CTX *ctx);

// Free internal buffers + heap-allocated CMAC context
CF_STATUS ll_CMAC_FreeAlloc(ll_CMAC_CTX **p_ctx);

// Verify a computed CMAC tag against an expected tag
CF_STATUS ll_CMAC_Verify(
    const ll_AES_KEY *key,
    const uint8_t *data, size_t data_len,
    const uint8_t *expected_tag, size_t tag_len);

// Clone a CMAC context into an existing destination
CF_STATUS ll_CMAC_CloneCtx(ll_CMAC_CTX *ctx_dest, const ll_CMAC_CTX *ctx_src);

// Clone and allocate a new heap CMAC context
ll_CMAC_CTX* ll_CMAC_CloneCtxAlloc(const ll_CMAC_CTX *ctx_src, CF_STATUS *status);

#ifdef __cplusplus
}
#endif

#endif // CMAC_H