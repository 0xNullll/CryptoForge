/*
 * CryptoForge - hmac.h / HMAC (HMAC-SHA-1, HMAC-SHA-2, and HMAC-SHA-3) Interface
 * Copyright (C) 2025 0xNullll
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#ifndef HMAC_H
#define HMAC_H

#include "../evp/evp_hash.h"
#include "../evp/evp_defs.h"
#include "../evp/evp_flags.h"

#include "../../utils/mem.h"
#include "../../utils/CF_status.h"

#include "../../config/libs.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================
// HMAC context structure
// ============================
typedef struct _ll_HMAC_CTX {
    const EVP_MD *md;                        // Low-level hash descriptor
    void *ipad_ctx;                          // Inner hash context
    void *opad_ctx;                          // Outer hash context
    size_t out_len;

    uint8_t key[EVP_MAX_KEY_SIZE];
    size_t key_len;

    int isFinalized;
    int isHeapAlloc; // 1 if allocated by library (heap), 0 if user stack    
} ll_HMAC_CTX;

// ============================
// HMAC low-level function prototypes
// ============================

// initializes a new HMAC_CTX for a given EVP_MD hash and key.
CF_STATUS ll_HMAC_Init(ll_HMAC_CTX *ctx, const EVP_MD *md, const uint8_t *key, size_t key_len);

// Allocates and initializes a new HMAC_CTX for a given EVP_MD hash and key.
// Returns NULL on allocation failure.
ll_HMAC_CTX* ll_HMAC_InitAlloc(const EVP_MD *md, const uint8_t *key, size_t key_len, CF_STATUS *status);

// Updates the HMAC with data. Can be called multiple times for streaming.
CF_STATUS ll_HMAC_Update(ll_HMAC_CTX *ctx, const uint8_t *data, size_t data_len);

// Finalizes the HMAC and writes the digest to the output buffer.
// digest_len should be at least the hash's digest_size.
CF_STATUS ll_HMAC_Final(ll_HMAC_CTX *ctx, uint8_t *digest, size_t digest_len);

// Frees internal buffers of a pre-allocated context
CF_STATUS ll_HMAC_Free(ll_HMAC_CTX *ctx);

// Frees internal buffers + the heap-allocated context
CF_STATUS ll_HMAC_FreeAlloc(ll_HMAC_CTX **p_ctx);

// Verifies if the provided HMAC matches the computed HMAC for the given data.
// Returns CF_SUCCESS if valid, CF_ERR if invalid.
CF_STATUS ll_HMAC_Verify(
    const EVP_MD *md, 
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    const uint8_t *expected_hmac, size_t expected_len
);

// Clone HMAC context into an existing destination context
CF_STATUS ll_HMAC_CloneCtx(ll_HMAC_CTX *ctx_dest, const ll_HMAC_CTX *ctx_src);

// Clone HMAC context and allocate a new heap context
ll_HMAC_CTX *ll_HMAC_CloneCtxAlloc(const ll_HMAC_CTX *ctx_src, CF_STATUS *status);

#ifdef __cplusplus
}
#endif

#endif // HMAC_H