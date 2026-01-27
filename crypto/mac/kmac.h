/*
 * CryptoForge - kmac.h / KMAC (KMAC-128, KMAC-XOF-128, and KMAC-256 and KMAC-XOF-256) Interface
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

#ifndef KMAC_H
#define KMAC_H

#include "../evp/evp_hash.h"
#include "../evp/evp_defs.h"
#include "../evp/evp_flags.h"

#include "../../utils/mem.h"
#include "../../utils/cf_status.h"

#include "../../config/libs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LL_KMAC_TYPE_IS_VALID(type) \
    ((type) == KMAC128 || (type) == KMAC256 || \
     (type) == KMACXOF128 || (type) == KMACXOF256)

#define LL_KMAC_IS_128(type) ((type) == KMAC128 || (type) == KMACXOF128)
#define LL_KMAC_IS_256(type) ((type) == KMAC256 || (type) == KMACXOF256)
#define LL_KMAC_IS_XOF(type) ((type) == KMACXOF128 || (type) == KMACXOF256)

#define LL_KMAC_DEFAULT_OUTPUT_LEN_128 16  // RFC fixed-length output for KMAC128
#define LL_KMAC_DEFAULT_OUTPUT_LEN_256 32  // RFC fixed-length output for KMAC256

typedef enum {
    KMAC128      = EVP_CAT_MAC | 0x0002,
    KMAC256      = EVP_CAT_MAC | 0x0003,
    KMACXOF128   = EVP_CAT_MAC | 0x0004,
    KMACXOF256   = EVP_CAT_MAC | 0x0005
} ll_KMAC_TYPE;

typedef struct _ll_KMAC_CTX {
    // Core CSHAKE sponge context
    void *cshake_ctx;

    // Key (raw bytes) and length
    uint8_t key[MAX_KEY_SIZE];
    size_t  key_len;

    // Requested output length in bytes (L in the spec)
    size_t out_len;

    // Customization strings
    uint8_t S[MAX_CUSTOMIZATION]; // Customization string (can be empty)
    size_t  S_len;

    // Bookkeeping flags
    int isFinalized;
    int customAbsorbed;     // 1 if N||S absorbed
    int emptyNameCustom;    // 1 if S are empty

    int isXOF;
    int isHeapAlloc;

    // KMAC variant
    ll_KMAC_TYPE type;      // e.g., KMAC128, KMAC256, KMACXOF128, KMACXOF256
} ll_KMAC_CTX;

// Initializes a new ll_KMAC_CTX for a given key, output length, and optional customization strings.
CF_STATUS ll_KMAC_Init(
    ll_KMAC_CTX *ctx,
    const uint8_t *key, size_t key_len,
    const uint8_t *S, size_t S_len,
    ll_KMAC_TYPE type      // varients: KMAC128, KMAC256, KMACXOF128, KMACXOF256
);

// Allocates and initializes a new ll_KMAC_CTX and Returns NULL on allocation failure.
ll_KMAC_CTX* ll_KMAC_InitAlloc(
    const uint8_t *key, size_t key_len,
    const uint8_t *S, size_t S_len,
    ll_KMAC_TYPE type,      // varients: KMAC128, KMAC256, KMACXOF128, KMACXOF256
    CF_STATUS *status
);

// Updates the KMAC with data. Can be called multiple times for streaming.
CF_STATUS ll_KMAC_Update(ll_KMAC_CTX *ctx, const uint8_t *data, size_t data_len);

// Finalizes the KMAC if not finalized already and writes the output to the digest buffer
CF_STATUS ll_KMAC_Final(ll_KMAC_CTX *ctx, uint8_t *digest, size_t digest_len);

// Verifies a standard fixed-length KMAC (KMAC128 or KMAC256) against expected output.
// Returns CF_SUCCESS if the output matches, CF_ERR_MAC_VERIFY if invalid.
// XOF variants are not allowed.
CF_STATUS ll_KMAC_Verify(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    const uint8_t *S, size_t S_len,
    const uint8_t *expected_mac,
    ll_KMAC_TYPE type);

// Resets a KMAC context to its initial state with the same key and customization strings.
CF_STATUS ll_KMAC_Free(ll_KMAC_CTX *ctx);

// Frees the ll_KMAC_CTX and its internal buffers.
CF_STATUS ll_KMAC_FreeAlloc(ll_KMAC_CTX **p_ctx);

// Clones a KMAC context into an existing destination context.
CF_STATUS ll_KMAC_CloneCtx(
    ll_KMAC_CTX *ctx_dest,
    const ll_KMAC_CTX *ctx_src
);

// Clones a KMAC context and allocates a new heap context.
ll_KMAC_CTX* ll_KMAC_CloneCtxAlloc(
    const ll_KMAC_CTX *ctx_src,
    CF_STATUS *status
);

#ifdef __cplusplus
}
#endif

#endif // KMAC_H