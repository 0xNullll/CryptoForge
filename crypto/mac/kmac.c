/*
 * CryptoForge - kmac.c / KMAC (KMAC-128, KMAC-XOF-128, and KMAC-256 and KMAC-XOF-256) Implementation
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

#include "../../include/crypto/kmac.h"

// Helper macros
#define ll_KMAC_INIT(ctx, name, name_len, S, S_len)                        \
    ((ctx)->type == LL_KMAC128 || (ctx)->type == LL_KMAC_XOF128               \
        ? ll_cshake128_init((ll_CSHAKE128_CTX*)(ctx)->cshake_ctx, (name), (name_len), (S), (S_len)) \
        : ll_cshake256_init((ll_CSHAKE256_CTX*)(ctx)->cshake_ctx, (name), (name_len), (S), (S_len)))

#define ll_KMAC_ABSORB(ctx, data, data_len)                                 \
    ((ctx)->type == LL_KMAC128 || (ctx)->type == LL_KMAC_XOF128                \
        ? ll_cshake128_absorb((ll_CSHAKE128_CTX*)(ctx)->cshake_ctx, (data), (data_len)) \
        : ll_cshake256_absorb((ll_CSHAKE256_CTX*)(ctx)->cshake_ctx, (data), (data_len)))

#define ll_KMAC_FINALIZE(ctx, buf, buf_len)                                   \
    ((ctx)->type == LL_KMAC128 || (ctx)->type == LL_KMAC_XOF128                   \
        ? (ll_cshake128_absorb((ll_CSHAKE128_CTX*)(ctx)->cshake_ctx, (buf), (buf_len)) && \
           ll_cshake128_final((ll_CSHAKE128_CTX*)(ctx)->cshake_ctx))      \
        : (ll_cshake256_absorb((ll_CSHAKE256_CTX*)(ctx)->cshake_ctx, (buf), (buf_len)) && \
           ll_cshake256_final((ll_CSHAKE256_CTX*)(ctx)->cshake_ctx)))

#define ll_KMAC_SQUEEZE(ctx, digest, len)                                    \
    ((ctx)->type == LL_KMAC128 || (ctx)->type == LL_KMAC_XOF128                   \
        ? ll_cshake128_squeeze((ll_CSHAKE128_CTX*)(ctx)->cshake_ctx, (digest), (len)) \
        : ll_cshake256_squeeze((ll_CSHAKE256_CTX*)(ctx)->cshake_ctx, (digest), (len)))

/*
 * See SP800-185 "Appendix A - KMAC, .... in Terms of Keccak[c]"
 *
 * Inputs are:
 *    K = Key                  (len(K) < 2^2040 bits)
 *    X = Input
 *    L = Output length        (0 <= L < 2^2040 bits)
 *    S = Customization String Default="" (len(S) < 2^2040 bits)
 *
 * KMAC128(K, X, L, S)
 * {
 *     newX = bytepad(encode_string(K), 168) ||  X || right_encode(L).
 *     T = bytepad(encode_string("KMAC") || encode_string(S), 168).
 *     return KECCAK[256](T || newX || 00, L).
 * }
 *
 * KMAC256(K, X, L, S)
 * {
 *     newX = bytepad(encode_string(K), 136) ||  X || right_encode(L).
 *     T = bytepad(encode_string("KMAC") || encode_string(S), 136).
 *     return KECCAK[512](T || newX || 00, L).
 * }
 *
 * KMAC128XOF(K, X, L, S)
 * {
 *     newX = bytepad(encode_string(K), 168) ||  X || right_encode(0).
 *     T = bytepad(encode_string("KMAC") || encode_string(S), 168).
 *     return KECCAK[256](T || newX || 00, L).
 * }
 *
 * KMAC256XOF(K, X, L, S)
 * {
 *     newX = bytepad(encode_string(K), 136) ||  X || right_encode(0).
 *     T = bytepad(encode_string("KMAC") || encode_string(S), 136).
 *     return KECCAK[512](T || newX || 00, L).
 * }
 *
 */

// computes the key for KMAC -> bytepad(encode_string(K), rate)
static size_t kmac_bytepad_encode_key(unsigned char *out, size_t out_max_len,
                                     size_t *out_len,
                                     const unsigned char *in, size_t in_len,
                                     size_t w) {
    unsigned char tmp[MAX_KEY_SIZE + MAX_ENCODED_HEADER_LEN];
    size_t tmp_len;

    // 1. Encode the key
    tmp_len = ll_encode_string(in, in_len, tmp, sizeof(tmp));
    if (tmp_len == 0) return 0;

    // 2. Bytepad the encoded string
    size_t padded_len = ll_byte_pad(tmp, tmp_len, w, out, out_max_len);
    if (out_len) *out_len = padded_len;

    return padded_len;
}

CF_STATUS ll_KMAC_Init(ll_KMAC_CTX *ctx,
                          const uint8_t *key, size_t key_len,
                          const uint8_t *S, size_t S_len,
                          LL_KMAC_TYPE type) {
    if (!ctx || !key)
        return CF_ERR_NULL_PTR;

    if ((key && key_len == 0) || (S && S_len == 0) || !LL_KMAC_TYPE_IS_VALID(type))
        return CF_ERR_INVALID_PARAM;

    if (key_len > MAX_KEY_SIZE || S_len > MAX_CUSTOMIZATION) 
        return CF_ERR_INVALID_LEN;

    ll_KMAC_Reset(ctx);
    
    ctx->type = type;
    ctx->isXOF = LL_KMAC_IS_XOF(ctx->type);

    // Allocate cSHAKE context
    if (LL_KMAC_IS_128(ctx->type)) {
        if (!ctx->cshake_ctx) ctx->cshake_ctx = SECURE_ALLOC(sizeof(ll_CSHAKE128_CTX));
    } else {
        if (!ctx->cshake_ctx) ctx->cshake_ctx = SECURE_ALLOC(sizeof(ll_CSHAKE256_CTX));
    }
    if (!ctx->cshake_ctx) return CF_ERR_ALLOC_FAILED;

    // Step 1: initialize cSHAKE with "KMAC" and customization
    if (!ll_KMAC_INIT(ctx, (const uint8_t*)"KMAC", 4, S, S_len))
        return CF_ERR_CTX_CORRUPT;

    // Step 2: encode + bytepad the key
    size_t rate_bytes = LL_KMAC_IS_128(ctx->type) ? CSHAKE128_BLOCK_SIZE : CSHAKE256_BLOCK_SIZE;
    uint8_t padded_key[2 * KECCAK_BLOCK_SIZE];
    size_t padded_len = kmac_bytepad_encode_key(padded_key, sizeof(padded_key),
                                                NULL, key, key_len, rate_bytes);
    if (padded_len == 0) return CF_ERR_INVALID_LEN;

    // Step 3: absorb bytepadded key
    if (!ll_KMAC_ABSORB(ctx, padded_key, padded_len)) return CF_ERR_CTX_CORRUPT;

    return CF_SUCCESS;
}

ll_KMAC_CTX *ll_KMAC_InitAlloc(
    const uint8_t *key, size_t key_len,
    const uint8_t *S, size_t S_len,
    LL_KMAC_TYPE type,
    CF_STATUS *status) {
    if (!key) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }
    
    if ((key && key_len == 0) || (S && S_len == 0) || !LL_KMAC_TYPE_IS_VALID(type)) {
        if (status) *status = CF_ERR_INVALID_PARAM;
        return NULL;
    }

        if (key_len > MAX_KEY_SIZE || S_len > MAX_CUSTOMIZATION) {
        if (status) *status = CF_ERR_INVALID_LEN;
        return NULL;
    }

    // Allocate memory for the context
    ll_KMAC_CTX *ctx = (ll_KMAC_CTX *)malloc(sizeof(ll_KMAC_CTX));
    if (!ctx) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Initialize the context
    if (!ll_KMAC_Init(ctx, key, key_len, S, S_len, type)) {
        free(ctx);
        if (status) *status = CF_ERR_CTX_CORRUPT;
        return NULL;
    }

    ctx->isHeapAlloc = 1;  // Mark as heap-allocated

    if (status) *status = CF_SUCCESS;
    return ctx;
}

CF_STATUS ll_KMAC_Update(ll_KMAC_CTX *ctx, const uint8_t *data, size_t data_len) {
    if (!ctx || !ctx->cshake_ctx)
        return CF_ERR_NULL_PTR;

    if (data_len > 0 && !data)
        return CF_ERR_INVALID_PARAM;

    if (ctx->isFinalized)
        return CF_ERR_HASH_FINALIZED;

    if (!ll_KMAC_ABSORB(ctx, data, data_len))
        return CF_ERR_CTX_CORRUPT;

    return CF_SUCCESS;
}

CF_STATUS ll_KMAC_Final(ll_KMAC_CTX *ctx, uint8_t *digest, size_t digest_len) {
    if (!ctx || !ctx->cshake_ctx || !digest) 
        return CF_ERR_NULL_PTR;

    if (digest_len == 0)
        return CF_ERR_INVALID_LEN;

    CF_STATUS ret = CF_SUCCESS;

    // Use the user-provided length for both XOF and normal KMAC
    size_t mac_len = digest_len;

    // If not finalized yet, store output length for subsequent squeezes
    if (!ctx->isFinalized) {
        ctx->out_len = mac_len;
    }

    // Already finalized? Just squeeze again
    if (ctx->isFinalized) {
        if (digest_len != ctx->out_len)
            return CF_ERR_INVALID_LEN;

        if (!ll_KMAC_SQUEEZE(ctx, digest, digest_len))
            return CF_ERR_CTX_CORRUPT;

        return CF_SUCCESS;
    }

    /* ---------- FIRST FINALIZATION PATH ---------- */

    // Temporary buffer for right_encode
    uint8_t tmp[MAX_CUSTOMIZATION + MAX_ENCODED_HEADER_LEN] = {0};
    size_t tmp_len;

    if (ctx->isXOF) {
        // For XOF, right_encode(0) per KMAC spec
        tmp_len = ll_right_encode_uint64(0, tmp);  // true XOF
    } else {
        // Multiply by 8 to convert bytes -> bits
        if (digest_len > (UINT64_MAX / 8)) 
            return CF_ERR_INVALID_LEN;  // prevent overflow

        tmp_len = ll_right_encode_uint64((uint64_t)digest_len * 8, tmp);
    }

    if (tmp_len == 0) {
        ret = CF_ERR_INVALID_LEN;
        goto cleanup;
    }

    // Finalize underlying cSHAKE with the encoded length
    if (!ll_KMAC_FINALIZE(ctx, tmp, tmp_len)) {
        ret = CF_ERR_CTX_CORRUPT;
        goto cleanup;
    }

    // Now squeeze the digest
    if (!ll_KMAC_SQUEEZE(ctx, digest, digest_len)) {
        ret = CF_ERR_CTX_CORRUPT;
        goto cleanup;
    }

    // Mark as finalized
    ctx->isFinalized = 1;

cleanup:
    SECURE_ZERO(tmp, sizeof(tmp));
    return ret;
}

#undef ll_KMAC_INIT
#undef ll_KMAC_ABSORB
#undef ll_KMAC_SQUEEZE
#undef ll_KMAC_FINALIZE

CF_STATUS ll_KMAC_Verify(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    const uint8_t *S, size_t S_len,
    const uint8_t *expected_mac,
    LL_KMAC_TYPE type) {
    if (!key || !data || !expected_mac)
        return CF_ERR_NULL_PTR;

    if (!LL_KMAC_TYPE_IS_VALID(type))
        return CF_ERR_INVALID_PARAM;

    if (LL_KMAC_IS_XOF(type))  // verification only for fixed-length output
        return CF_ERR_UNSUPPORTED;

    CF_STATUS status = CF_SUCCESS;
    ll_KMAC_CTX ctx;
    uint8_t computed[CF_MAX_DEFAULT_DIGEST_SIZE] = {0};

    SECURE_ZERO(&ctx, sizeof(ctx));

    // Initialize
    status = ll_KMAC_Init(&ctx, key, key_len, S, S_len, type);
    if (status != CF_SUCCESS) goto cleanup;

    // Update with message data
    if (data_len > 0) {
        status = ll_KMAC_Update(&ctx, data, data_len);
        if (status != CF_SUCCESS) goto cleanup;
    }

    // Determine MAC length based on type
    size_t mac_len = (type == LL_KMAC128) ? LL_KMAC_DEFAULT_OUTPUT_LEN_128
                                       : LL_KMAC_DEFAULT_OUTPUT_LEN_256;

    // Finalize
    status = ll_KMAC_Final(&ctx, computed, mac_len);
    if (status != CF_SUCCESS) goto cleanup;

    // Constant-time comparison
    status = SECURE_MEM_EQUAL(computed, expected_mac, mac_len) ? CF_SUCCESS : CF_ERR_MAC_VERIFY;

cleanup:
    SECURE_ZERO(&ctx, sizeof(ctx));
    SECURE_ZERO(computed, sizeof(computed));
    return status;
}

// Frees internal buffers of a pre-allocated KMAC context
CF_STATUS ll_KMAC_Reset(ll_KMAC_CTX *ctx) {
    if (!ctx) return CF_ERR_NULL_PTR;
    if (!LL_KMAC_TYPE_IS_VALID(ctx->type)) return CF_ERR_UNSUPPORTED;

    int wasHeapAlloc = ctx->isHeapAlloc;

    // Free underlying CSHAKE context
    if (ctx->cshake_ctx) {
        if (ctx->type == LL_KMAC128 || ctx->type == LL_KMAC_XOF128)
            SECURE_FREE(ctx->cshake_ctx, sizeof(ll_CSHAKE128_CTX));
        else
            SECURE_FREE(ctx->cshake_ctx, sizeof(ll_CSHAKE256_CTX));
        ctx->cshake_ctx = NULL;
    }

    // Clear key and customization
    SECURE_ZERO(ctx->key, sizeof(ctx->key));
    SECURE_ZERO(ctx->S, sizeof(ctx->S));

    // Reset bookkeeping flags
    ctx->key_len = 0;
    ctx->out_len = 0;
    ctx->S_len = 0;
    ctx->isFinalized = 0;
    ctx->customAbsorbed = 0;
    ctx->emptyNameCustom = 1;
    ctx->isHeapAlloc = wasHeapAlloc;

    return CF_SUCCESS;
}

CF_STATUS ll_KMAC_Free(ll_KMAC_CTX **p_ctx) {
    if (!p_ctx || !*p_ctx) return CF_ERR_NULL_PTR;

    ll_KMAC_CTX *ctx = *p_ctx;
    int wasHeapAlloc = ctx->isHeapAlloc;

    ll_KMAC_Reset(ctx);

    if (wasHeapAlloc) {
        SECURE_ZERO(ctx, sizeof(ll_KMAC_CTX));
        SECURE_FREE(ctx, sizeof(ll_KMAC_CTX));
        *p_ctx = NULL;
    }

    return CF_SUCCESS;
}

CF_STATUS ll_KMAC_CloneCtx(ll_KMAC_CTX *ctx_dest, const ll_KMAC_CTX *ctx_src) {
    if (!ctx_dest || !ctx_src)
        return CF_ERR_NULL_PTR;

    SECURE_ZERO(ctx_dest, sizeof(*ctx_dest));

    // Clone CSHAKE context if present
    if (ctx_src->cshake_ctx) {
        size_t cshake_ctx_size = LL_KMAC_IS_128(ctx_src->type) ? CSHAKE128_BLOCK_SIZE : CSHAKE256_BLOCK_SIZE;

        ctx_dest->cshake_ctx = SECURE_ALLOC(cshake_ctx_size);
        if (!ctx_dest->cshake_ctx)
            return CF_ERR_ALLOC_FAILED;

        SECURE_MEMCPY(ctx_dest->cshake_ctx, ctx_src->cshake_ctx, cshake_ctx_size);
    } else {
        ctx_dest->cshake_ctx = NULL;
    }

    // Copy key and customization arrays
    ctx_dest->key_len = ctx_src->key_len;
    if (ctx_dest->key_len)
        SECURE_MEMCPY(ctx_dest->key, ctx_src->key, ctx_dest->key_len);

    ctx_dest->S_len = ctx_src->S_len;
    if (ctx_dest->S_len)
        SECURE_MEMCPY(ctx_dest->S, ctx_src->S, ctx_dest->S_len);

    // Copy output length
    ctx_dest->out_len = ctx_src->out_len;

    // Copy flags
    ctx_dest->isFinalized      = ctx_src->isFinalized;
    ctx_dest->customAbsorbed   = ctx_src->customAbsorbed;
    ctx_dest->emptyNameCustom  = ctx_src->emptyNameCustom;
    ctx_dest->isXOF            = ctx_src->isXOF;
    ctx_dest->isHeapAlloc      = 0; // always caller-managed

    // Copy KMAC type
    ctx_dest->type = ctx_src->type;

    return CF_SUCCESS;
}

ll_KMAC_CTX *ll_KMAC_CloneCtxAlloc(const ll_KMAC_CTX *ctx_src, CF_STATUS *status) {
    if (!ctx_src) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    // Allocate a new ll_KMAC_CTX on the heap
    ll_KMAC_CTX *ctx_dest = (ll_KMAC_CTX *)SECURE_ALLOC(sizeof(ll_KMAC_CTX));
    if (!ctx_dest) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Zero-initialize the new context
    SECURE_ZERO(ctx_dest, sizeof(ll_KMAC_CTX));

    // Use existing clone function to copy contents
    CF_STATUS ret = ll_KMAC_CloneCtx(ctx_dest, ctx_src);
    if (ret != CF_SUCCESS) {
        SECURE_FREE(ctx_dest, sizeof(ll_KMAC_CTX));
        if (status) *status = ret;
        return NULL;
    }

    ctx_dest->isHeapAlloc = 1; // library owns this memory

    if (status) *status = CF_SUCCESS;
    return ctx_dest;
}
