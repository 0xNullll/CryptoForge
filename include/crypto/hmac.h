/*
 * CryptoForge - hmac.h / HMAC (HMAC-SHA-1, HMAC-SHA-2, and HMAC-SHA-3) Interface
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against WyChaProof test vectors. No hardware optimizations. Use with caution.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#ifndef HMAC_H
#define HMAC_H

#include "../cf_api/cf_hash.h"
#include "../cf_api/cf_defs.h"
#include "../cf_api/cf_flags.h"

#include "../utils/mem.h"
#include "../utils/cf_status.h"

#include "../config/libs.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================
// HMAC context structure
// ============================
typedef struct _ll_HMAC_CTX {
    const CF_MD *md;                        // Low-level hash descriptor

    uint8_t ipad_ctx[CF_MAX_HASH_CTX_SIZE];
    uint8_t opad_ctx[CF_MAX_HASH_CTX_SIZE];
    size_t out_len;

    uint8_t key[CF_MAX_KEY_SIZE];
    size_t key_len;

    int isFinalized;
    int isHeapAlloc;
} ll_HMAC_CTX;

// ============================
// HMAC low-level function prototypes
// ============================

// initializes a new HMAC_CTX for a given CF_MD hash and key.
CF_STATUS ll_HMAC_Init(ll_HMAC_CTX *ctx, const CF_MD *md, const uint8_t *key, size_t key_len);

// Allocates and initializes a new HMAC_CTX for a given CF_MD hash and key.
// Returns NULL on allocation failure.
ll_HMAC_CTX* ll_HMAC_InitAlloc(const CF_MD *md, const uint8_t *key, size_t key_len, CF_STATUS *status);

// Updates the HMAC with data. Can be called multiple times for streaming.
CF_STATUS ll_HMAC_Update(ll_HMAC_CTX *ctx, const uint8_t *data, size_t data_len);

// Finalizes the HMAC and writes the digest to the output buffer.
// digest_len should be at least the hash's digest_size.
CF_STATUS ll_HMAC_Final(ll_HMAC_CTX *ctx, uint8_t *digest, size_t digest_len);

// Verifies if the provided HMAC matches the computed HMAC for the given data.
// Returns CF_SUCCESS if valid, CF_ERR_MAC_VERIFY if invalid.
CF_STATUS ll_HMAC_Verify(
    const CF_MD *md, 
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    const uint8_t *expected_tag, size_t expected_tag_len
);

// Frees internal buffers of a pre-allocated context
CF_STATUS ll_HMAC_Reset(ll_HMAC_CTX *ctx);

// Frees internal buffers + the heap-allocated context
CF_STATUS ll_HMAC_Free(ll_HMAC_CTX **p_ctx);

// Clone HMAC context into an existing destination context
CF_STATUS ll_HMAC_CloneCtx(ll_HMAC_CTX *ctx_dest, const ll_HMAC_CTX *ctx_src);

// Clone HMAC context and allocate a new heap context
ll_HMAC_CTX *ll_HMAC_CloneCtxAlloc(const ll_HMAC_CTX *ctx_src, CF_STATUS *status);

#ifdef __cplusplus
}
#endif

#endif // HMAC_H