/*
 * CryptoForge - poly1305.h / Poly1305 Interface
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

#ifndef POLY1305_H
#define POLY1305_H

#include "../utils/mem.h"
#include "../utils/cf_status.h"
#include "../utils/bitops.h"

#include "../config/libs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LL_POLY1305_KEY_LEN   32   // 256-bit one-time key (r || s)
#define LL_POLY1305_TAG_LEN   16   // 128-bit authentication tag
#define LL_POLY1305_BLOCK_LEN 16   // message block size

// ============================
// Poly1305 context structure
// ============================
typedef struct _ll_POLY1305_CTX {
    /* r and s parts of the key (little-endian) */
    uint32_t r[4];        // clamped r (130-bit representation)
    uint32_t s[4];        // s (128-bit)

    /* accumulator (130-bit) */
    uint32_t acc[5];

    /* partial block buffer */
    uint8_t  buffer[LL_POLY1305_BLOCK_LEN];
    size_t   buffer_len;

    int isFinalized;
    int isHeapAlloc;
} ll_POLY1305_CTX;

// ============================
// Poly1305 low-level API
// ============================

// Initialize Poly1305 context with a 32-byte one-time key
CF_STATUS ll_POLY1305_Init(ll_POLY1305_CTX *ctx, const uint8_t key[LL_POLY1305_KEY_LEN]);

// Allocate + initialize Poly1305 context
ll_POLY1305_CTX* ll_POLY1305_InitAlloc(const uint8_t key[LL_POLY1305_KEY_LEN], CF_STATUS *status);

// Update Poly1305 with message data
CF_STATUS ll_POLY1305_Update(ll_POLY1305_CTX *ctx, const uint8_t *data, size_t data_len);

// Finalize Poly1305 and output authentication tag
CF_STATUS ll_POLY1305_Final(ll_POLY1305_CTX *ctx, uint8_t tag[LL_POLY1305_TAG_LEN]);

// Verify Poly1305 tag (constant-time compare)
CF_STATUS ll_POLY1305_Verify(
    const uint8_t key[LL_POLY1305_KEY_LEN],
    const uint8_t *data, size_t data_len,
    const uint8_t expected_tag[LL_POLY1305_TAG_LEN]
);

// Reset internal state (clears accumulator, buffer, flags)
CF_STATUS ll_POLY1305_Reset(ll_POLY1305_CTX *ctx);

// Free internal buffers of a heap-allocated context
CF_STATUS ll_POLY1305_Free(ll_POLY1305_CTX **p_ctx);

// Clone a Poly1305 context into an existing destination
CF_STATUS ll_POLY1305_CloneCtx(ll_POLY1305_CTX *ctx_dest, const ll_POLY1305_CTX *ctx_src);

// Clone and allocate a new Poly1305 context
ll_POLY1305_CTX* ll_POLY1305_CloneCtxAlloc(const ll_POLY1305_CTX *ctx_src, CF_STATUS *status);

#ifdef __cplusplus
}
#endif

#endif // POLY1305_H