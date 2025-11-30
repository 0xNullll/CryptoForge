#include "kmac.h"

// Helper macros
#define ll_KMAC_INIT(ctx, name, name_len, S, S_len)                        \
    ((ctx)->type == KMAC128 || (ctx)->type == KMACXOF128               \
        ? ll_cshake128_init((ll_CSHAKE128_CTX*)(ctx)->cshake_ctx, (name), (name_len), (S), (S_len)) \
        : ll_cshake256_init((ll_CSHAKE256_CTX*)(ctx)->cshake_ctx, (name), (name_len), (S), (S_len)))

#define ll_KMAC_ABSORB(ctx, data, data_len)                                 \
    ((ctx)->type == KMAC128 || (ctx)->type == KMACXOF128                \
        ? ll_cshake128_absorb((ll_CSHAKE128_CTX*)(ctx)->cshake_ctx, (data), (data_len)) \
        : ll_cshake256_absorb((ll_CSHAKE256_CTX*)(ctx)->cshake_ctx, (data), (data_len)))

#define ll_KMAC_FINALIZE(ctx, buf, buf_len)                                   \
    ((ctx)->type == KMAC128 || (ctx)->type == KMACXOF128                   \
        ? (ll_cshake128_absorb((ll_CSHAKE128_CTX*)(ctx)->cshake_ctx, (buf), (buf_len)) && \
           ll_cshake128_final((ll_CSHAKE128_CTX*)(ctx)->cshake_ctx))      \
        : (ll_cshake256_absorb((ll_CSHAKE256_CTX*)(ctx)->cshake_ctx, (buf), (buf_len)) && \
           ll_cshake256_final((ll_CSHAKE256_CTX*)(ctx)->cshake_ctx)))

#define ll_KMAC_SQUEEZE(ctx, digest, len)                                    \
    ((ctx)->type == KMAC128 || (ctx)->type == KMACXOF128                   \
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

// -------------------------- Init --------------------------
TCLIB_STATUS ll_KMAC_Init(ll_KMAC_CTX *ctx,
                          const uint8_t *key, size_t key_len,
                          const uint8_t *custom, size_t custom_len,
                          ll_KMAC_TYPE type) {
    if (!ctx || !LL_KMAC_TYPE_IS_VALID(type)) return TCLIB_ERR_NULL_PTR;
    if (key_len > MAX_KEY_SIZE || custom_len > MAX_CUSTOMIZATION) return TCLIB_ERR_INVALID_LEN;

    memset(ctx, 0, sizeof(*ctx));
    ctx->type = type;
    ctx->isXOF = LL_KMAC_IS_XOF(ctx);
    ctx->out_len = LL_KMAC_IS_128(ctx) ? CSHAKE128_DEFAULT_OUT_LEN : CSHAKE256_DEFAULT_OUT_LEN; // 32 bytes = 256-bit, 64 bytes = 512-bit

    // Allocate cSHAKE context
    if (LL_KMAC_IS_128(ctx)) {
        if (!ctx->cshake_ctx) ctx->cshake_ctx = malloc(sizeof(ll_CSHAKE128_CTX));
    } else {
        if (!ctx->cshake_ctx) ctx->cshake_ctx = malloc(sizeof(ll_CSHAKE256_CTX));
    }
    if (!ctx->cshake_ctx) return TCLIB_ERR_ALLOC_FAILED;

    // Step 1: initialize cSHAKE with "KMAC" and customization
    if (!ll_KMAC_INIT(ctx, (const uint8_t*)"KMAC", 4, custom, custom_len))
        return TCLIB_ERR_CTX_CORRUPT;

    // Step 2: encode + bytepad the key
    size_t rate_bytes = LL_KMAC_IS_128(ctx) ? CSHAKE128_BLOCK_SIZE : CSHAKE256_BLOCK_SIZE;
    uint8_t padded_key[2 * KECCAK_BLOCK_SIZE];
    size_t padded_len = kmac_bytepad_encode_key(padded_key, sizeof(padded_key),
                                                NULL, key, key_len, rate_bytes);
    if (padded_len == 0) return TCLIB_ERR_INVALID_LEN;

    // Step 3: absorb bytepadded key
    if (!ll_KMAC_ABSORB(ctx, padded_key, padded_len)) return TCLIB_ERR_CTX_CORRUPT;

    ctx->customAbsorbed = 1;
    ctx->isHeapAlloc = 0;

    return TCLIB_SUCCESS;
}

ll_KMAC_CTX *ll_KMAC_InitAlloc(
    const uint8_t *key, size_t key_len,
    const uint8_t *S, size_t S_len,
    ll_KMAC_TYPE type,
    TCLIB_STATUS *status) {
    if (key_len > MAX_KEY_SIZE || S_len > MAX_CUSTOMIZATION) {
        if (status) *status = TCLIB_ERR_INVALID_LEN;
        return NULL;
    }

    if (!LL_KMAC_TYPE_IS_VALID(type)) {
        if (status) *status = TCLIB_ERR_UNSUPPORTED;
        return NULL;
    }

    // Allocate memory for the context
    ll_KMAC_CTX *ctx = (ll_KMAC_CTX *)malloc(sizeof(ll_KMAC_CTX));
    if (!ctx) {
        if (status) *status = TCLIB_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Initialize the context
    if (!ll_KMAC_Init(ctx, key, key_len, S, S_len, type)) {
        free(ctx);
        if (status) *status = TCLIB_ERR_CTX_CORRUPT;
        return NULL;
    }

    ctx->isHeapAlloc = 1;  // Mark as heap-allocated

    if (status) *status = TCLIB_SUCCESS;
    return ctx;
}

// -------------------------- Update --------------------------
TCLIB_STATUS ll_KMAC_Update(ll_KMAC_CTX *ctx, const uint8_t *data, size_t data_len) {
    if (!ctx || !ctx->cshake_ctx)
        return TCLIB_ERR_NULL_PTR;

    if (data_len > 0 && !data)
        return TCLIB_ERR_INVALID_PARAM;

    if (ctx->isFinalized)
        return TCLIB_ERR_HASH_FINALIZED;

    if (!ll_KMAC_ABSORB(ctx, data, data_len))
        return TCLIB_ERR_CTX_CORRUPT;

    return TCLIB_SUCCESS;
}

// -------------------------- Final --------------------------
TCLIB_STATUS ll_KMAC_Final(ll_KMAC_CTX *ctx, uint8_t *digest, size_t digest_len) {
    if (!ctx || !ctx->cshake_ctx || !digest) return TCLIB_ERR_NULL_PTR;

    size_t final_len = digest_len ? digest_len : ctx->out_len;

    if (!ctx->isXOF && !ctx->isFinalized)
        ctx->out_len = final_len;

    // already finalized → just squeeze
    if (ctx->isFinalized) {
        if (!ctx->isXOF && final_len != ctx->out_len) return TCLIB_ERR_INVALID_LEN;
        if (!ll_KMAC_SQUEEZE(ctx, digest, final_len)) return TCLIB_ERR_CTX_CORRUPT;
        return TCLIB_SUCCESS;
    }

    /* ---------- FIRST FINALIZATION PATH ---------- */

    uint8_t tmp[MAX_CUSTOMIZATION + MAX_ENCODED_HEADER_LEN];

    // right_encode(L) or right_encode(0)
    size_t tmp_len = ctx->isXOF ? ll_right_encode_uint64(0, tmp)
                                : ll_right_encode_uint64((uint64_t)final_len * 8, tmp);

    if (tmp_len == 0) return TCLIB_ERR_INVALID_LEN;

    // Finalize underlying cSHAKE with encoded length
    if (!ll_KMAC_FINALIZE(ctx, tmp, tmp_len))
        return TCLIB_ERR_CTX_CORRUPT;

    // Now squeeze
    if (!ll_KMAC_SQUEEZE(ctx, digest, final_len))
        return TCLIB_ERR_CTX_CORRUPT;

    ctx->isFinalized = 1;
    return TCLIB_SUCCESS;
}

// Frees internal buffers of a pre-allocated KMAC context
TCLIB_STATUS ll_KMAC_Free(ll_KMAC_CTX *ctx) {
    if (!ctx) return TCLIB_ERR_NULL_PTR;
    if (!LL_KMAC_TYPE_IS_VALID(ctx->type)) return TCLIB_ERR_UNSUPPORTED;

    // Free underlying CSHAKE context
    if (ctx->cshake_ctx) {
        if (ctx->type == KMAC128 || ctx->type == KMACXOF128)
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
    ctx->out_len = (ctx->type == KMAC128) ? CSHAKE128_DEFAULT_OUT_LEN :
                   (ctx->type == KMAC256) ? CSHAKE256_DEFAULT_OUT_LEN : 0;
    ctx->S_len = 0;
    ctx->isFinalized = 0;
    ctx->customAbsorbed = 0;
    ctx->emptyNameCustom = 1;
    ctx->isHeapAlloc = 0;

    return TCLIB_SUCCESS;
}

// Frees internal buffers + the heap-allocated KMAC context
TCLIB_STATUS ll_KMAC_FreeAlloc(ll_KMAC_CTX **p_ctx) {
    if (!p_ctx || !*p_ctx) return TCLIB_ERR_NULL_PTR;

    ll_KMAC_CTX *ctx = *p_ctx;
    int wasHeapAlloc = ctx->isHeapAlloc;  // save flag

    // Reuse Free to clean internals
    ll_KMAC_Free(ctx);

    // Free the outer struct if heap-allocated
    if (wasHeapAlloc) {
        SECURE_ZERO(ctx, sizeof(ll_KMAC_CTX));
        SECURE_FREE(ctx, sizeof(ll_KMAC_CTX));
        *p_ctx = NULL;
    }

    return TCLIB_SUCCESS;
}

#undef ll_KMAC_INIT
#undef ll_KMAC_ABSORB
#undef ll_KMAC_SQUEEZE
#undef ll_KMAC_FINALIZE