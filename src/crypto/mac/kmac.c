/*
 * CryptoForge - kmac.c / KMAC (KMAC-128, KMAC-XOF-128, and KMAC-256 and KMAC-XOF-256) Implementation
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

#include "../../include/crypto/kmac.h"

// Helper macros
#define LL_CSHAKE_INIT(ctx, name, name_len, S, S_len)                        \
    ((ctx)->type == LL_KMAC128 || (ctx)->type == LL_KMAC_XOF128               \
        ? ll_cshake128_init((ll_CSHAKE128_CTX*)(ctx)->cshake_ctx, (name), (name_len), (S), (S_len)) \
        : ll_cshake256_init((ll_CSHAKE256_CTX*)(ctx)->cshake_ctx, (name), (name_len), (S), (S_len)))

#define LL_CSHAKE_ABSORB(ctx, data, data_len)                                 \
    ((ctx)->type == LL_KMAC128 || (ctx)->type == LL_KMAC_XOF128                \
        ? ll_cshake128_absorb((ll_CSHAKE128_CTX*)(ctx)->cshake_ctx, (data), (data_len)) \
        : ll_cshake256_absorb((ll_CSHAKE256_CTX*)(ctx)->cshake_ctx, (data), (data_len)))

#define LL_CSHAKE_FINALIZE(ctx, buf, buf_len)                                   \
    ((ctx)->type == LL_KMAC128 || (ctx)->type == LL_KMAC_XOF128                   \
        ? (ll_cshake128_absorb((ll_CSHAKE128_CTX*)(ctx)->cshake_ctx, (buf), (buf_len)) && \
           ll_cshake128_final((ll_CSHAKE128_CTX*)(ctx)->cshake_ctx))      \
        : (ll_cshake256_absorb((ll_CSHAKE256_CTX*)(ctx)->cshake_ctx, (buf), (buf_len)) && \
           ll_cshake256_final((ll_CSHAKE256_CTX*)(ctx)->cshake_ctx)))

#define LL_CSHAKE_SQUEEZE(ctx, digest, len)                                    \
    ((ctx)->type == LL_KMAC128 || (ctx)->type == LL_KMAC_XOF128                   \
        ? ll_cshake128_squeeze((ll_CSHAKE128_CTX*)(ctx)->cshake_ctx, (digest), (len)) \
        : ll_cshake256_squeeze((ll_CSHAKE256_CTX*)(ctx)->cshake_ctx, (digest), (len)))

/*
 * See NIST SP 800-185, Sections 4–4.3.1 (KMAC) for details on the Keccak[c]-based construction.
 *
 * Inputs:
 *    K = Key                   (len(K) < 2^2040 bits)
 *    X = Input
 *    L = Output length         (0 <= L < 2^2040 bits)
 *    S = Customization String  Default="" (len(S) < 2^2040 bits)
 *
 * KMAC128(K, X, L, S)
 * {
 *     newX = bytepad(encode_string(K), 168) || X || right_encode(L)
 *     T    = bytepad(encode_string("KMAC") || encode_string(S), 168)
 *     return KECCAK[256](T || newX || 0x00, L)
 * }
 *
 * KMAC256(K, X, L, S)
 * {
 *     newX = bytepad(encode_string(K), 136) || X || right_encode(L)
 *     T    = bytepad(encode_string("KMAC") || encode_string(S), 136)
 *     return KECCAK[512](T || newX || 0x00, L)
 * }
 *
 * KMAC128XOF(K, X, L, S)
 * {
 *     newX = bytepad(encode_string(K), 168) || X || right_encode(0)
 *     T    = bytepad(encode_string("KMAC") || encode_string(S), 168)
 *     return KECCAK[256](T || newX || 0x00, L)
 * }
 *
 * KMAC256XOF(K, X, L, S)
 * {
 *     newX = bytepad(encode_string(K), 136) || X || right_encode(0)
 *     T    = bytepad(encode_string("KMAC") || encode_string(S), 136)
 *     return KECCAK[512](T || newX || 0x00, L)
 * }
 */

static bool kmac_absorb_key(ll_KMAC_CTX *ctx, const uint8_t *key, size_t key_len, size_t rate_bytes) {
    if (!ctx || !key) return false;

    // left-encode rate (w) and absorb
    uint8_t le_w[CSHAKE_MAX_ENCODED_HEADER_LEN];
    size_t le_w_len = ll_left_encode_uint64(rate_bytes, le_w);
    if (!LL_CSHAKE_ABSORB(ctx, le_w, le_w_len))
        return false;

    // left-encode key bit-length and absorb
    uint8_t le_key[CSHAKE_MAX_ENCODED_HEADER_LEN];
    size_t le_key_len = ll_left_encode_uint64((uint64_t)key_len * 8, le_key);
    if (!LL_CSHAKE_ABSORB(ctx, le_key, le_key_len))
        return false;

    // absorb the key
    if (!LL_CSHAKE_ABSORB(ctx, key, key_len))
        return false;

    // zero padding to reach multiple of rate
    size_t total_len = le_w_len + le_key_len + key_len;
    size_t pad_len = (rate_bytes - (total_len % rate_bytes)) % rate_bytes;
    uint8_t zeros[64] = {0};
    while (pad_len > 0) {
        size_t chunk = pad_len > sizeof(zeros) ? sizeof(zeros) : pad_len;
        if (!LL_CSHAKE_ABSORB(ctx, zeros, chunk))
            return false;
        pad_len -= chunk;
    }

    return true;
}

CF_STATUS ll_KMAC_Init(ll_KMAC_CTX *ctx, const uint8_t *key, size_t key_len, const uint8_t *S, size_t S_len, LL_KMAC_TYPE type) {
    if (!ctx || !key)
        return CF_ERR_NULL_PTR;

    if (!LL_KMAC_TYPE_IS_VALID(type))
        return CF_ERR_INVALID_PARAM;

    if (key_len == 0 && (S && S_len == 0))
        return CF_ERR_INVALID_LEN;

    if (ctx->isHeapAlloc != 0 && ctx->isHeapAlloc != 1)
        return CF_ERR_CTX_UNINITIALIZED;

    ll_KMAC_Reset(ctx);
    ctx->type = type;
    ctx->isXOF = LL_KMAC_IS_XOF(ctx->type);

    // Allocate cSHAKE context on heap if needed
    if (LL_KMAC_IS_128(ctx->type)) {
        if (!ctx->cshake_ctx) ctx->cshake_ctx = SECURE_ALLOC(sizeof(ll_CSHAKE128_CTX));
    } else {
        if (!ctx->cshake_ctx) ctx->cshake_ctx = SECURE_ALLOC(sizeof(ll_CSHAKE256_CTX));
    }
    if (!ctx->cshake_ctx) return CF_ERR_ALLOC_FAILED;

    // initialize cSHAKE with "KMAC" and customization
    if (!LL_CSHAKE_INIT(ctx, (const uint8_t*)"KMAC", 4, S, S_len))
        return CF_ERR_CTX_CORRUPT;

    // streaming absorb key using proper SP800-185 logic
    size_t rate_bytes = LL_KMAC_IS_128(ctx->type) ? CSHAKE128_BLOCK_SIZE : CSHAKE256_BLOCK_SIZE;
    if (!kmac_absorb_key(ctx, key, key_len, rate_bytes))
        return CF_ERR_CTX_CORRUPT;

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
    
    if (!LL_KMAC_TYPE_IS_VALID(type)) {
        if (status) *status = CF_ERR_INVALID_PARAM;
        return NULL;
    }

        if (key_len == 0 || (S && S_len == 0)) {
        if (status) *status = CF_ERR_INVALID_LEN;
        return NULL;
    }

    // Allocate memory for the context
    ll_KMAC_CTX *ctx = (ll_KMAC_CTX *)SECURE_ALLOC(sizeof(ll_KMAC_CTX));
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
    if (!ctx || !ctx->cshake_ctx || !data)
        return CF_ERR_NULL_PTR;

    if (ctx->isFinalized)
        return CF_ERR_HASH_FINALIZED;

    if (!LL_CSHAKE_ABSORB(ctx, data, data_len))
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
        if (!ctx->isXOF && digest_len != ctx->out_len)
            return CF_ERR_INVALID_LEN;  // only enforce for fixed-length KMAC

        if (!LL_CSHAKE_SQUEEZE(ctx, digest, digest_len))
            return CF_ERR_CTX_CORRUPT;

        return CF_SUCCESS;
    }

    // First finalization
    uint8_t tmp[CSHAKE_MAX_ENCODED_HEADER_LEN];  // max for right_encode_uint64
    size_t tmp_len;

    if (ctx->isXOF) {
        // For XOF, right_encode(0) per KMAC spec
        tmp_len = ll_right_encode_uint64(0, tmp);  // XOF mode
    } else {
        // Multiply by 8 to convert bytes -> bits
        if (digest_len > (UINT64_MAX / 8))
            return CF_ERR_INVALID_LEN; // prevent overflow

        tmp_len = ll_right_encode_uint64((uint64_t)digest_len * 8, tmp); // bytes -> bits
    }

    if (tmp_len == 0)
        return CF_ERR_INVALID_LEN;

    // Finalize underlying cSHAKE with the encoded length
    if (!LL_CSHAKE_FINALIZE(ctx, tmp, tmp_len)) {
        ret = CF_ERR_CTX_CORRUPT;
        goto cleanup;
    }
    ctx->isFinalized = 1;

    // squeeze digest
    if (!LL_CSHAKE_SQUEEZE(ctx, digest, digest_len)) {
        ret = CF_ERR_CTX_CORRUPT;
        goto cleanup;
    }

cleanup:
    SECURE_ZERO(tmp, sizeof(tmp));
    return ret;
}

#undef LL_CSHAKE_INIT
#undef LL_CSHAKE_ABSORB
#undef LL_CSHAKE_FINALIZE
#undef LL_CSHAKE_SQUEEZE

// Frees internal buffers of a pre-allocated KMAC context
CF_STATUS ll_KMAC_Reset(ll_KMAC_CTX *ctx) {
    if (!ctx)
        return CF_ERR_NULL_PTR;
    
    if (!LL_KMAC_TYPE_IS_VALID(ctx->type))
        return CF_ERR_CTX_CORRUPT;

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
    ctx->key = NULL;
    ctx->S   = NULL;

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

    // Free the outer struct if heap-allocated
    if (wasHeapAlloc)
        SECURE_FREE(ctx, sizeof(ll_KMAC_CTX));

    return CF_SUCCESS;
}

CF_STATUS ll_KMAC_Verify(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    const uint8_t *S, size_t S_len,
    const uint8_t *expected_tag,
    size_t expected_tag_len,   // allow arbitrary tag length
    LL_KMAC_TYPE type) {
    if (!key || !data || !expected_tag)
        return CF_ERR_NULL_PTR;

    if (!LL_KMAC_TYPE_IS_VALID(type))
        return CF_ERR_INVALID_PARAM;

    CF_STATUS status = CF_SUCCESS;
    ll_KMAC_CTX ctx = {0};

    // Determine MAC length based on type and user input
    size_t tag_len = expected_tag_len;
    uint8_t stack_computed_tag[CF_MAX_DEFAULT_DIGEST_SIZE] = {0};
    uint8_t *computed_tag = NULL;

    // Choose buffer: use stack if small enough, heap if needed
    if (tag_len <= sizeof(stack_computed_tag)) {
        computed_tag = stack_computed_tag;
    } else {
        computed_tag = (uint8_t *)SECURE_ALLOC(tag_len);
        if (!computed_tag)
            return CF_ERR_ALLOC_FAILED;
        SECURE_ZERO(computed_tag, tag_len);
    }

    status = ll_KMAC_Init(&ctx, key, key_len, S, S_len, type);
    if (status != CF_SUCCESS) goto cleanup;

    status = ll_KMAC_Update(&ctx, data, data_len);
    if (status != CF_SUCCESS) goto cleanup;

    status = ll_KMAC_Final(&ctx, computed_tag, tag_len);
    if (status != CF_SUCCESS) goto cleanup;

    // Constant-time comparison
    status = SECURE_MEM_EQUAL(computed_tag, expected_tag, tag_len) ? CF_SUCCESS : CF_ERR_MAC_VERIFY;

cleanup:
    ll_KMAC_Reset(&ctx);
    if (computed_tag != stack_computed_tag)
        SECURE_FREE(computed_tag, tag_len);
    else
        SECURE_ZERO(computed_tag, sizeof(stack_computed_tag));

    return status;
}

CF_STATUS ll_KMAC_CloneCtx(ll_KMAC_CTX *ctx_dest, const ll_KMAC_CTX *ctx_src) {
    if (!ctx_dest || !ctx_src)
        return CF_ERR_NULL_PTR;

    // Zero the destination first
    ll_KMAC_Reset(ctx_dest);

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
    ctx_dest->key     = ctx_src->key;
    ctx_dest->key_len = ctx_src->key_len;
    ctx_dest->S       = ctx_src->S;
    ctx_dest->S_len   = ctx_src->S_len;

    // Copy output length
    ctx_dest->out_len = ctx_src->out_len;

    // Copy flags
    ctx_dest->isFinalized      = ctx_src->isFinalized;
    ctx_dest->customAbsorbed   = ctx_src->customAbsorbed;
    ctx_dest->emptyNameCustom  = ctx_src->emptyNameCustom;
    ctx_dest->isXOF            = ctx_src->isXOF;
    ctx_dest->isHeapAlloc      = 0; // dst is “new”, caller owns it

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
