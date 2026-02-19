/*
 * CryptoForge - cf_aead.c / High-level AEAD Cipher context implementation
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

#include "../../include/cf_api/cf_aead.h"

//
// Wrappers for all hashes
//

// AES-GCM
static bool aes_gcm_init_wrapper(const CF_AEAD_CTX *ctx) {
    return ll_AES_GCM_Init((ll_AES_GCM_CTX *)ctx->aead_ctx, (const ll_AES_KEY *)ctx->key_ctx, ctx->iv, ctx->iv_len, ctx->aad, ctx->aad_len, ctx->operation);
}
static bool aes_gcm_update_wrapper(const CF_AEAD_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out) {
    return ll_AES_GCM_Update((ll_AES_GCM_CTX *)ctx->aead_ctx, in, in_len, out);
}
static bool aes_gcm_final_wrapper(const CF_AEAD_CTX *ctx, uint8_t *tag, size_t tag_len) {
    return ll_AES_GCM_Final((ll_AES_GCM_CTX *)ctx->aead_ctx, tag, tag_len);
}

// ChaCha20-Poly1305
static bool chacha20_poly1305_init_wrapper(const CF_AEAD_CTX *ctx) {
    return ll_CHACHA20_POLY1305_Init((ll_CHACHA20_POLY1305_CTX *)ctx->aead_ctx, ctx->key, ctx->iv, ctx->aad, ctx->aad_len, ctx->operation);
}
static bool chacha20_poly1305_update_wrapper(const CF_AEAD_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out) {
    return ll_CHACHA20_POLY1305_Update((ll_CHACHA20_POLY1305_CTX *)ctx->aead_ctx, in, in_len, out);
}
static bool chacha20_poly1305_final_wrapper(const CF_AEAD_CTX *ctx, uint8_t *tag, size_t tag_len) {
    UNUSED(tag_len);
    return ll_CHACHA20_POLY1305_Final((ll_CHACHA20_POLY1305_CTX *)ctx->aead_ctx, tag);
}

// XChaCha20-Poly1305
static bool xchacha20_poly1305_init_wrapper(const CF_AEAD_CTX *ctx) {
    return ll_XCHACHA20_POLY1305_Init((ll_XCHACHA20_POLY1305_CTX *)ctx->aead_ctx, ctx->key, ctx->iv, ctx->aad, ctx->aad_len, ctx->operation);
}
static bool xchacha20_poly1305_update_wrapper(const CF_AEAD_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out) {
    return ll_XCHACHA20_POLY1305_Update((ll_XCHACHA20_POLY1305_CTX *)ctx->aead_ctx, in, in_len, out);
}
static bool xchacha20_poly1305_final_wrapper(const CF_AEAD_CTX *ctx, uint8_t *tag, size_t tag_len) {
    UNUSED(tag_len);
    return ll_XCHACHA20_POLY1305_Final((ll_XCHACHA20_POLY1305_CTX *)ctx->aead_ctx, tag);
}

//
// AES-GCM
//
static const CF_AEAD *CF_get_aes_gcm(void) {
    static CF_AEAD aead = {
        .id = CF_AES_GCM,
        .ctx_size = sizeof(ll_AES_GCM_CTX),
        .key_ctx_size = sizeof(ll_AES_KEY),
        .aead_init_fn = aes_gcm_init_wrapper,
        .aead_update_fn = aes_gcm_update_wrapper,
        .aead_final_fn = aes_gcm_final_wrapper
    };
    return &aead;
}

//
// ChaCha20-Poly1305
//
static const CF_AEAD *CF_get_chacha20_poly1305(void) {
    static CF_AEAD aead = {
        .id = CF_CHACHA20_POLY1305,
        .ctx_size = sizeof(ll_CHACHA20_POLY1305_CTX),
        .key_ctx_size = 0,
        .aead_init_fn = chacha20_poly1305_init_wrapper,
        .aead_update_fn = chacha20_poly1305_update_wrapper,
        .aead_final_fn = chacha20_poly1305_final_wrapper
    };
    return &aead;
}

//
// XChaCha20-Poly1305
//
static const CF_AEAD *CF_get_xchacha20_poly1305(void) {
    static CF_AEAD aead = {
        .id = CF_XCHACHA20_POLY1305,
        .ctx_size = sizeof(ll_XCHACHA20_POLY1305_CTX),
        .key_ctx_size = 0,
        .aead_init_fn = xchacha20_poly1305_init_wrapper,
        .aead_update_fn = xchacha20_poly1305_update_wrapper,
        .aead_final_fn = xchacha20_poly1305_final_wrapper
    };
    return &aead;
}

// Table of all supported AEAD aeads
static const CF_ALGO_ENTRY cf_aead_table[] = {
    { CF_AES_GCM,             (const void* (*)(void))CF_get_aes_gcm            },
    { CF_CHACHA20_POLY1305,   (const void* (*)(void))CF_get_chacha20_poly1305  },
    { CF_XCHACHA20_POLY1305,  (const void* (*)(void))CF_get_xchacha20_poly1305 }
};

const CF_AEAD *CF_AEAD_GetByFlag(uint32_t algo_flag) {
    if (!CF_IS_AEAD(algo_flag)) 
        return NULL;

    size_t table_len = sizeof(cf_aead_table) / sizeof(cf_aead_table[0]);
    for (size_t i = 0; i < table_len; i++) {
        if (cf_aead_table[i].flag == algo_flag) {
            return (const CF_AEAD*)cf_aead_table[i].getter_fn();
        }
    }
    return NULL;
}

CF_STATUS CF_AEAD_Init(
    CF_AEAD_CTX *ctx, const CF_AEAD *aead,
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *aad, size_t aad_len,
    CF_OPERATION op) {
    if (!ctx || !aead || !key || !iv)
        return CF_ERR_NULL_PTR;

   // Validate that the aead type is recognized
    if (!CF_IS_AEAD(aead->id))
        return CF_ERR_UNSUPPORTED;

    // Validate heap allocation flag
    if (ctx->isHeapAlloc != 0 && ctx->isHeapAlloc != 1)
        return CF_ERR_CTX_UNINITIALIZED;

    // Ensure operation is either encryption or decryption
    if (op != CF_OP_ENCRYPT && op != CF_OP_DECRYPT)
        return CF_ERR_INVALID_PARAM;

    // Reset context to a clean state
    CF_AEAD_Reset(ctx);

    // Store core context parameters
    ctx->aead      = aead;
    ctx->key       = key;
    ctx->key_len   = key_len;
    ctx->iv        = iv;
    ctx->iv_len    = iv_len;
    ctx->aad       = aad;
    ctx->aad_len   = aad_len;
    ctx->operation = op;

    // AES-specific initialization/checks
    if (CF_IS_AES_AEAD(ctx->aead->id)) {

        // Check AES key length
        if (!CF_IS_AES_KEY_VALID(ctx->key_len))
            return CF_ERR_CIPHER_INVALID_KEY_LEN;

        // Check AES nonce Length minimum
        if (ctx->iv_len < AES_GCM_IV_MIN)
            return CF_ERR_AEAD_INVALID_IV;

        // Check AES AAD Length limits
        if (ctx->aad_len > AES_GCM_AAD_MAX_DATA_LEN)
            return CF_ERR_AEAD_INVALID_AAD;

        // Allocate memory for AES key schedule
        ctx->key_ctx = (void *)SECURE_ALLOC(ctx->aead->key_ctx_size);
        if (!ctx->key_ctx)
            return CF_ERR_ALLOC_FAILED;

        // Initialize AES key schedule
        if (!ll_AES_SetEncryptKey((ll_AES_KEY *)ctx->key_ctx, ctx->key, ctx->key_len)) {
            CF_AEAD_Reset(ctx);
            return CF_ERR_CIPHER_KEY_SETUP;
        }

    }
    // ChaCha-specific checks
    else if (CF_IS_CHACHA_AEAD(ctx->aead->id)) {

        // Check ChaCha20/XChaCha20 key length
        if (!CF_IS_CHACHA_AEAD_KEY_VALID(ctx->key_len))
            return CF_ERR_CIPHER_INVALID_KEY_LEN;

        if (ctx->aead->id == CF_CHACHA20_POLY1305) {
            if (ctx->iv_len != CHACHA20_POLY1305_IV_SIZE)
                return CF_ERR_AEAD_INVALID_IV;
        } else {
            if (ctx->iv_len != XCHACHA_EXTENDED_IV_SIZE)
                return CF_ERR_AEAD_INVALID_IV;
        }

        // Check ChaCha AAD Length limits
        if (ctx->aad_len > CHACHA20_POLY1305_MAX_AAD_LEN)
            return CF_ERR_AEAD_INVALID_AAD;

    }
    else {
        // Unsupported AEAD cipher type
        return CF_ERR_UNSUPPORTED;
    }

    // Reject contexts with invalid size
    if (ctx->aead->ctx_size == 0)
        return CF_ERR_CTX_CORRUPT;

    // Allocate memory for AEAD internal context
    ctx->aead_ctx = (void *)SECURE_ALLOC(ctx->aead->ctx_size);
    if (!ctx->aead_ctx) {
        // Reset context on allocation failure
        CF_AEAD_Reset(ctx);
        return CF_ERR_ALLOC_FAILED;
    }

    // Call the AEAD-specific initialization function
    if (!ctx->aead->aead_init_fn(ctx)) {
        // Reset context if initialization fails
        CF_AEAD_Reset(ctx);
        return CF_ERR_CTX_CORRUPT;
    }

    // Bind magic value for context integrity checking
    // Detects accidental misuse or memory corruption
    ctx->magic = CF_CTX_MAGIC ^ (uintptr_t)ctx->aead;

    return CF_SUCCESS;
}

CF_AEAD_CTX* CF_AEAD_InitAlloc(
    const CF_AEAD *aead,
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *aad, size_t aad_len,
    CF_OPERATION op, CF_STATUS *status) {
    if (!aead) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    // Validate operation mode
    if (op != CF_OP_ENCRYPT && op != CF_OP_DECRYPT) {
        if (status) *status = CF_ERR_INVALID_PARAM;
        return NULL;
    }

    // Allocate memory for a new cipher context on the heap
    CF_AEAD_CTX *ctx = (CF_AEAD_CTX *)SECURE_ALLOC(sizeof(CF_AEAD_CTX));
    if (!ctx) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Initialize the newly allocated AEAD cipher context
    CF_STATUS st = CF_AEAD_Init(ctx, aead, key, key_len, iv, iv_len, aad, aad_len, op);
    if (st != CF_SUCCESS) {
        // Reset and free memory if initialization failed
        CF_AEAD_Reset(ctx);
        SECURE_FREE(ctx, sizeof(CF_AEAD_CTX));
        if (status) *status = st;
        return NULL;
    }

    // Mark context as heap-allocated for proper cleanup later
    ctx->isHeapAlloc = 1;

    // Return success status to caller
    if (status) *status = CF_SUCCESS;
    return ctx;
}

CF_STATUS CF_AEAD_Update(
    CF_AEAD_CTX *ctx,
    const uint8_t *in, size_t in_len,
    uint8_t *out) {
    if (!ctx || !in || !out)
        return CF_ERR_NULL_PTR;

    // Ensure the AEAD descriptor are initialized
    if (!ctx->aead || !ctx->aead_ctx)
        return CF_ERR_CTX_UNINITIALIZED;

    // Verify integrity of the context using the bound "magic" value
    // Detects accidental corruption or misuse of the context
    if ((ctx->magic ^ (uintptr_t)ctx->aead) != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    if (CF_IS_AES_AEAD(ctx->aead->id)) {

        if (!ctx->key_ctx)
            return CF_ERR_CTX_UNINITIALIZED;

    if (ctx->total_data_len + in_len > AES_GCM_MAX_DATA_LEN)
        return CF_ERR_LIMIT_EXCEEDED;

    }
    else if (CF_IS_CHACHA_AEAD(ctx->aead->id)) {

    if (ctx->total_data_len + in_len > CHACHA20_POLY1305_MAX_DATA_LEN)
        return CF_ERR_LIMIT_EXCEEDED;

    }

    if (!ctx->aead->aead_update_fn(ctx, in, in_len, out))
        return CF_ERR_CTX_CORRUPT;

    ctx->total_data_len += in_len;

    return CF_SUCCESS;
}

CF_STATUS CF_AEAD_Final(
    CF_AEAD_CTX *ctx,
    uint8_t *tag, size_t tag_len) {
    if (!ctx || !tag)
        return CF_ERR_NULL_PTR;

    // Ensure the AEAD descriptor are initialized
    if (!ctx->aead || !ctx->aead_ctx)
        return CF_ERR_CTX_UNINITIALIZED;

    // Verify integrity of the context using the bound "magic" value
    // Detects accidental corruption or misuse of the context
    if ((ctx->magic ^ (uintptr_t)ctx->aead) != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    if (CF_IS_AES_AEAD(ctx->aead->id)) {

        if (!ctx->key_ctx)
            return CF_ERR_CTX_UNINITIALIZED;

        if (!IS_VALID_GCM_TAG_SIZE(tag_len))
            return CF_ERR_MAC_INVALID_TAG_LEN;

    }

    if (!ctx->aead->aead_final_fn(ctx, tag, tag_len))
        return CF_ERR_CTX_CORRUPT;

    return CF_SUCCESS;
}

CF_STATUS CF_AEAD_Reset(CF_AEAD_CTX *ctx) {
    if (!ctx)
        return CF_ERR_NULL_PTR;

    if (!ctx->aead)
        return CF_ERR_CTX_UNINITIALIZED;

    if (ctx->aead_ctx) {
        if (ctx->aead->ctx_size == 0)
            return CF_ERR_CTX_CORRUPT;
        SECURE_FREE(ctx->aead_ctx, ctx->aead->ctx_size);
    }

    if (ctx->key_ctx) {
        if (ctx->aead->key_ctx_size == 0)
            return CF_ERR_CTX_CORRUPT;
        SECURE_FREE(ctx->key_ctx, ctx->aead->key_ctx_size);
    }

    ctx->aead           = NULL;
    ctx->key            = NULL;
    ctx->iv             = NULL;
    ctx->aad            = NULL;
    ctx->key_len        = 0;
    ctx->iv_len         = 0;
    ctx->aad_len        = 0;
    ctx->total_data_len = 0;
    ctx->operation      = 0;
    ctx->magic          = 0;

    return CF_SUCCESS;
}

CF_STATUS CF_AEAD_Free(CF_AEAD_CTX **p_ctx) {
    if (!p_ctx || !*p_ctx)
        return CF_ERR_NULL_PTR;

    CF_AEAD_CTX *ctx = *p_ctx;

    CF_AEAD_Reset(ctx);

    if (ctx->isHeapAlloc) {
        SECURE_ZERO(ctx, sizeof(CF_AEAD_CTX));
        *p_ctx = NULL;
    }

    return CF_SUCCESS; 
}

static FORCE_INLINE CF_STATUS CF_AEAD_EncDec(
    const CF_AEAD *aead,
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *in, size_t in_len,
    uint8_t *out, uint8_t *tag, size_t tag_len,
    CF_OPERATION op) {
    if (!aead || !key || !iv || !tag)
        return CF_ERR_NULL_PTR;

    // Stack-allocated AEAD Cipher context for one-shot operation
    CF_AEAD_CTX ctx = {0};
    CF_STATUS st = CF_SUCCESS;

    st = CF_AEAD_Init(&ctx, aead, key, key_len, iv, iv_len, aad, aad_len, op);

    // Verify initialization succeeded and context integrity is intact
    // The magic check detects accidental corruption or misuse
    if (st != CF_SUCCESS || (ctx.magic ^ (uintptr_t)ctx.aead) != CF_CTX_MAGIC)
        goto cleanup;

    // Process input buffer (encrypt or decrypt depending on 'op')
    // Output is written to 'out'
    st = CF_AEAD_Update(&ctx, in, in_len, out);
    if (st != CF_SUCCESS || (ctx.magic ^ (uintptr_t)ctx.aead) != CF_CTX_MAGIC)
        goto cleanup;

    st = CF_AEAD_Final(&ctx, tag, tag_len);

cleanup:
    // Securely clear context regardless of success or failure
    CF_AEAD_Reset(&ctx);

    return st;
}

CF_STATUS CF_AEAD_Encrypt(
    const CF_AEAD *aead,
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *in, size_t in_len,
    uint8_t *out, uint8_t *tag, size_t tag_len) {
    return CF_AEAD_EncDec(aead, key, key_len, iv, iv_len, aad, aad_len, in, in_len, out, tag, tag_len, CF_OP_ENCRYPT);
}

CF_STATUS CF_AEAD_Decrypt(
    const CF_AEAD *aead,
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *in, size_t in_len,
    uint8_t *out, uint8_t *tag, size_t tag_len) {
    return CF_AEAD_EncDec(aead, key, key_len, iv, iv_len, aad, aad_len, in, in_len, out, tag, tag_len, CF_OP_DECRYPT);
}

CF_STATUS CF_AEAD_CloneCtx(CF_AEAD_CTX *dst, const CF_AEAD_CTX *src) {
    if (!dst || !src)
        return CF_ERR_NULL_PTR;

    // Ensure the AEAD cipher descriptor exists
    if (!src->aead)
        return CF_ERR_CTX_UNINITIALIZED;

    // Verify integrity of the context using the bound "magic" value
    // Detects accidental corruption or misuse of the context
    if ((src->magic ^ (uintptr_t)src->aead) != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    // Reset the AEAD Cipher context to a clean state
    CF_AEAD_Reset(dst);

    // Copy metadata (shallow)
    dst->magic          = src->magic;
    dst->aead           = src->aead;
    dst->key            = src->key;
    dst->key_len        = src->key_len;
    dst->iv             = src->iv;
    dst->iv_len         = src->iv_len;
    dst->aad_len        = src->aad_len;
    dst->total_data_len = src->total_data_len;
    dst->operation      = src->operation;
    dst->isHeapAlloc    = 0;

    CF_STATUS st = CF_SUCCESS;

    // Deep copy low-level key context
    if (src->key_ctx) {
        if (src->aead->key_ctx_size == 0)
            return CF_ERR_CTX_CORRUPT;

        dst->key_ctx = SECURE_ALLOC(src->aead->key_ctx_size);
        if (!dst->key_ctx) {
            st = CF_ERR_ALLOC_FAILED;
            goto cleanup;
        }

        SECURE_MEMCPY(dst->key_ctx, src->key_ctx, src->aead->key_ctx_size);
    }

    // Deep copy low-level cipher context
    if (src->aead_ctx) {
        dst->aead_ctx = SECURE_ALLOC(src->aead->ctx_size);
        if (!dst->aead_ctx) {
            st = CF_ERR_ALLOC_FAILED;
            goto cleanup;
        }

        SECURE_MEMCPY(dst->aead_ctx, src->aead_ctx, src->aead->ctx_size);
    }

    return st;

cleanup:
    // Cleanup partially allocated memory
    if (dst->key_ctx && src->aead->key_ctx_size)
        SECURE_FREE(dst->key_ctx, src->aead->key_ctx_size);

    if (dst->aead_ctx && src->aead->ctx_size)
        SECURE_FREE(dst->aead_ctx, src->aead->ctx_size);

    return st;
}

CF_AEAD_CTX* CF_AEAD_CloneCtxAlloc(const CF_AEAD_CTX *src, CF_STATUS *status) {
    if (!src) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    CF_AEAD_CTX *dst = (CF_AEAD_CTX *)SECURE_ALLOC(sizeof(CF_AEAD_CTX));
    if (!dst) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Deep copy contents
    CF_STATUS ret = CF_AEAD_CloneCtx(dst, src);
    if (ret != CF_SUCCESS) {
        if (status) *status = ret;
        CF_AEAD_Free(&dst);
        return NULL;
    }

    // cloned context is heap-allocated
    dst->isHeapAlloc = 1;

    if (status) *status = CF_SUCCESS;
    return dst;
}

CF_STATUS CF_AEAD_ValidateCtx(const CF_AEAD_CTX *ctx) {
    if (!ctx)
        return CF_ERR_NULL_PTR;

    // Verify context integrity using the bound magic value
    // Detects accidental corruption or misuse of the encoder context
    if ((ctx->magic ^ (uintptr_t)ctx->aead) != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    return CF_SUCCESS;
}

const char* CF_AEAD_GetName(const CF_AEAD *aead) {
    if (!aead)
        return "NULL";

    switch (aead->id) {
        case CF_AES_GCM:             return "AES-GCM";

        case CF_CHACHA20_POLY1305:   return "ChaCha20-Poly1305";
        case CF_XCHACHA20_POLY1305:  return "XChaCha20-Poly1305";
        
        default: 
            return "UNKNOWN-AEAD";
    }
}

const char* CF_AEAD_GetFullName(const CF_AEAD_CTX *ctx) {
    if (!ctx || !ctx->aead) return "NULL";

    switch (ctx->aead->id) {
        case CF_AES_GCM:
            switch (ctx->key_len) {
                case CF_KEY_128_SIZE: return "AES-128-GCM";
                case CF_KEY_192_SIZE: return "AES-192-GCM";
                case CF_KEY_256_SIZE: return "AES-256-GCM";
                default: return "AES-GCM-UNKNOWN";
            }
        case CF_CHACHA20_POLY1305:  return "ChaCha20-Poly1305";
        case CF_XCHACHA20_POLY1305: return "XChaCha20-Poly1305";
        default: return "UNKNOWN-AEAD";
    }
}

bool CF_AEAD_IsValidKeyLength(const CF_AEAD *aead, size_t key_len) {
    if (!aead)
        return false;

    if (CF_IS_AES_AEAD(aead->id)) {
       if (CF_IS_AES_KEY_VALID(key_len))
        return true;
    }
    else if (CF_IS_CHACHA_AEAD(aead->id)) {
       if (CF_IS_CHACHA_AEAD_KEY_VALID(key_len))
        return true;
    }

    return false;
}

bool CF_AEAD_IsValidTagLength(const CF_AEAD *aead, size_t tag_len) {
    if (!aead)
        return false;

    if (CF_IS_AES_AEAD(aead->id)) {
       if (CF_IS_VALID_GCM_TAG_SIZE(tag_len))
        return true;
    }
    else if (CF_IS_CHACHA_AEAD(aead->id)) {
       if (CF_IS_VALID_CHACHA_TAG_SIZE(tag_len))
        return true;
    }

    return false;
}

const size_t* CF_AEAD_GetValidKeySizes(const CF_AEAD *aead, size_t *count) {
    if (!aead || !count)
        return NULL;

    static const size_t aes_sizes[3] = {CF_KEY_128_SIZE, CF_KEY_192_SIZE, CF_KEY_256_SIZE};
    static const size_t chacha_sizes[2] = {CF_KEY_256_SIZE};

    if (CF_IS_AES_AEAD(aead->id)) {
        *count = 3;
        return aes_sizes;
    } else if (CF_IS_CHACHA_AEAD(aead->id)) {
        *count = 2;
        return chacha_sizes;
    }

    *count = 0;
    return NULL;
}

const size_t* CF_AEAD_GetValidTagSizes(const CF_AEAD *aead, size_t *count) {
    if (!aead || !count)
        return NULL;

    static const size_t aes_sizes[4] = {CF_AEAD_TAG_32_SIZE, CF_AEAD_TAG_64_SIZE, CF_AEAD_TAG_96_SIZE, CF_AEAD_TAG_128_SIZE};
    static const size_t chacha_sizes[1] = {CF_AEAD_TAG_128_SIZE};

    if (CF_IS_AES_AEAD(aead->id)) {
        *count = 4;
        return aes_sizes;
    } else if (CF_IS_CHACHA_AEAD(aead->id)) {
        *count = 1;
        return chacha_sizes;
    }

    *count = 0;
    return NULL;
}