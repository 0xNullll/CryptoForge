/*
 * CryptoForge - cf_cipher.c / High-level Cipher context implementation
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against WyChaProof test vectors. No hardware optimizations. Use with caution.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#include "../../include/cf_api/cf_cipher.h"

//
// Wrappers for all hashes
//

// AES-ECB
static bool aes_ecb_enc_wrapper(const CF_CIPHER_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out, const CF_CIPHER_OPTS *opts) {
    UNUSED(opts);
    return ll_AES_ECB_Encrypt((const ll_AES_KEY *)ctx->key_ctx, in, in_len, out);
}
static bool aes_ecb_dec_wrapper(const CF_CIPHER_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out, const CF_CIPHER_OPTS *opts) {
    UNUSED(opts);
    return ll_AES_ECB_Decrypt((const ll_AES_KEY *)ctx->key_ctx, in, in_len, out);
}

// AES-CBC
static bool aes_cbc_enc_wrapper(const CF_CIPHER_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out, const CF_CIPHER_OPTS *opts) {
    return ll_AES_CBC_Encrypt((const ll_AES_KEY *)ctx->key_ctx, opts->iv, in, in_len, out);
}
static bool aes_cbc_dec_wrapper(const CF_CIPHER_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out, const CF_CIPHER_OPTS *opts) {
    return ll_AES_CBC_Decrypt((const ll_AES_KEY *)ctx->key_ctx, opts->iv, in, in_len, out);
}

// AES-OFB
static bool aes_ofb_enc_wrapper(const CF_CIPHER_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out, const CF_CIPHER_OPTS *opts) {
    return ll_AES_OFB_Encrypt((const ll_AES_KEY *)ctx->key_ctx, opts->iv, in, in_len, out);
}
static bool aes_ofb_dec_wrapper(const CF_CIPHER_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out, const CF_CIPHER_OPTS *opts) {
    return ll_AES_OFB_Decrypt((const ll_AES_KEY *)ctx->key_ctx, opts->iv, in, in_len, out);
}

// AES-CFB8
static bool aes_cfb8_enc_wrapper(const CF_CIPHER_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out, const CF_CIPHER_OPTS *opts) {
    return ll_AES_CFB8_Encrypt((const ll_AES_KEY *)ctx->key_ctx, opts->iv, in, in_len, out);
}
static bool aes_cfb8_dec_wrapper(const CF_CIPHER_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out, const CF_CIPHER_OPTS *opts) {
    return ll_AES_CFB8_Decrypt((const ll_AES_KEY *)ctx->key_ctx, opts->iv, in, in_len, out);
}

// AES-CFB128
static bool aes_cfb128_enc_wrapper(const CF_CIPHER_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out, const CF_CIPHER_OPTS *opts) {
    return ll_AES_CFB128_Encrypt((const ll_AES_KEY *)ctx->key_ctx, opts->iv, in, in_len, out);
}
static bool aes_cfb128_dec_wrapper(const CF_CIPHER_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out, const CF_CIPHER_OPTS *opts) {
    return ll_AES_CFB128_Decrypt((const ll_AES_KEY *)ctx->key_ctx, opts->iv, in, in_len, out);
}

// AES-CTR
static bool aes_ctr_enc_wrapper(const CF_CIPHER_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out, const CF_CIPHER_OPTS *opts) {
    return ll_AES_CTR_Encrypt((const ll_AES_KEY *)ctx->key_ctx, opts->ctr_block, in, in_len, out);
}
static bool aes_ctr_dec_wrapper(const CF_CIPHER_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out, const CF_CIPHER_OPTS *opts) {
    return ll_AES_CTR_Decrypt((const ll_AES_KEY *)ctx->key_ctx, opts->ctr_block, in, in_len, out);
}

// ChaCha8
static bool chacha8_init_wrapper(CF_CIPHER_CTX *ctx, CF_CIPHER_OPTS *opts) {
    return ll_CHACHA8_Init((ll_CHACHA8_CTX *)ctx->cipher_ctx, ctx->key, ctx->key_len, opts->iv, opts->chacha_counter);
}
static bool chacha8_cipher_wrapper(const CF_CIPHER_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out, const CF_CIPHER_OPTS *opts) {
    UNUSED(opts);
    return ll_CHACHA8_Cipher((ll_CHACHA8_CTX *)ctx->cipher_ctx, in, in_len, out);
}

// ChaCha12
static bool chacha12_init_wrapper(CF_CIPHER_CTX *ctx, CF_CIPHER_OPTS *opts) {
    return ll_CHACHA12_Init((ll_CHACHA12_CTX *)ctx->cipher_ctx, ctx->key, ctx->key_len, opts->iv, opts->chacha_counter);
}
static bool chacha12_cipher_wrapper(const CF_CIPHER_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out, const CF_CIPHER_OPTS *opts) {
    UNUSED(opts);
    return ll_CHACHA12_Cipher((ll_CHACHA12_CTX *)ctx->cipher_ctx, in, in_len, out);
}

// ChaCha20
static bool chacha20_init_wrapper(CF_CIPHER_CTX *ctx, CF_CIPHER_OPTS *opts) {
    return ll_CHACHA20_Init((ll_CHACHA20_CTX *)ctx->cipher_ctx, ctx->key, ctx->key_len, opts->iv, opts->chacha_counter);
}
static bool chacha20_cipher_wrapper(const CF_CIPHER_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out, const CF_CIPHER_OPTS *opts) {
    UNUSED(opts);
    return ll_CHACHA20_Cipher((ll_CHACHA20_CTX *)ctx->cipher_ctx, in, in_len, out);
}

// XChaCha8
static bool xchacha8_init_wrapper(CF_CIPHER_CTX *ctx, CF_CIPHER_OPTS *opts) {
    return ll_XCHACHA8_Init((ll_XCHACHA8_CTX *)ctx->cipher_ctx, ctx->key, opts->iv);
}
static bool xchacha8_cipher_wrapper(const CF_CIPHER_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out, const CF_CIPHER_OPTS *opts) {
    UNUSED(opts);
    return ll_XCHACHA8_Cipher((ll_XCHACHA8_CTX *)ctx->cipher_ctx, in, in_len, out);
}

// XChaCha12
static bool xchacha12_init_wrapper(CF_CIPHER_CTX *ctx, CF_CIPHER_OPTS *opts) {
    return ll_XCHACHA12_Init((ll_XCHACHA12_CTX *)ctx->cipher_ctx, ctx->key, opts->iv);
}
static bool xchacha12_cipher_wrapper(const CF_CIPHER_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out, const CF_CIPHER_OPTS *opts) {
    UNUSED(opts);
    return ll_XCHACHA12_Cipher((ll_XCHACHA12_CTX *)ctx->cipher_ctx, in, in_len, out);
}


// XChaCha20
static bool xchacha20_init_wrapper(CF_CIPHER_CTX *ctx, CF_CIPHER_OPTS *opts) {
    return ll_XCHACHA20_Init((ll_XCHACHA20_CTX *)ctx->cipher_ctx, ctx->key, opts->iv);
}
static bool xchacha20_cipher_wrapper(const CF_CIPHER_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out, const CF_CIPHER_OPTS *opts) {
    UNUSED(opts);
    return ll_XCHACHA20_Cipher((ll_XCHACHA20_CTX *)ctx->cipher_ctx, in, in_len, out);
}

// --- CF_cipher Return Functions ---

//
// AES-ECB
//
static const CF_CIPHER *CF_get_aes_ecb(void) {
    static CF_CIPHER cipher = {
        .id = CF_AES_ECB,
        .ctx_size = 0,
        .key_ctx_size = sizeof(ll_AES_KEY),
        .block_size = AES_BLOCK_SIZE,
        .cipher_init_fn = NULL,
        .cipher_enc_fn = aes_ecb_enc_wrapper,
        .cipher_dec_fn = aes_ecb_dec_wrapper
    };
    return &cipher;
}

//
// AES-CBC
//
static const CF_CIPHER *CF_get_aes_cbc(void) {
    static CF_CIPHER cipher = {
        .id = CF_AES_CBC,
        .ctx_size = 0,
        .key_ctx_size = sizeof(ll_AES_KEY),
        .block_size = AES_BLOCK_SIZE,
        .cipher_init_fn = NULL,
        .cipher_enc_fn = aes_cbc_enc_wrapper,
        .cipher_dec_fn = aes_cbc_dec_wrapper
    };
    return &cipher;
}

//
// AES-OFB
//
static const CF_CIPHER *CF_get_aes_ofb(void) {
    static CF_CIPHER cipher = {
        .id = CF_AES_OFB,
        .ctx_size = 0,
        .key_ctx_size = sizeof(ll_AES_KEY),
        .block_size = 0,
        .cipher_init_fn = NULL,
        .cipher_enc_fn = aes_ofb_enc_wrapper,
        .cipher_dec_fn = aes_ofb_dec_wrapper
    };
    return &cipher;
}

//
// AES-CFB8
//
static const CF_CIPHER *CF_get_aes_cfb8(void) {
    static CF_CIPHER cipher = {
        .id = CF_AES_CFB8,
        .ctx_size = 0,
        .key_ctx_size = sizeof(ll_AES_KEY),
        .block_size = 0,
        .cipher_init_fn = NULL,
        .cipher_enc_fn = aes_cfb8_enc_wrapper,
        .cipher_dec_fn = aes_cfb8_dec_wrapper
    };
    return &cipher;
}

//
// AES-CFB128
//
static const CF_CIPHER *CF_get_aes_cfb128(void) {
    static CF_CIPHER cipher = {
        .id = CF_AES_CFB128,
        .ctx_size = 0,
        .key_ctx_size = sizeof(ll_AES_KEY),
        .block_size = 0,
        .cipher_init_fn = NULL,
        .cipher_enc_fn = aes_cfb128_enc_wrapper,
        .cipher_dec_fn = aes_cfb128_dec_wrapper
    };
    return &cipher;
}

//
// AES-CTR
//
static const CF_CIPHER *CF_get_aes_ctr(void) {
    static CF_CIPHER cipher = {
        .id = CF_AES_CTR,
        .ctx_size = 0,
        .key_ctx_size = sizeof(ll_AES_KEY),
        .block_size = 0,
        .cipher_init_fn = NULL,
        .cipher_enc_fn = aes_ctr_enc_wrapper,
        .cipher_dec_fn = aes_ctr_dec_wrapper
    };
    return &cipher;
}

//
// ChaCha8
//
static const CF_CIPHER *CF_get_chacha8(void) {
    static CF_CIPHER cipher = {
        .id = CF_CHACHA8,
        .ctx_size = sizeof(ll_CHACHA8_CTX),
        .key_ctx_size = 0,
        .block_size = 0,
        .cipher_init_fn = chacha8_init_wrapper,
        .cipher_enc_fn = chacha8_cipher_wrapper,
        .cipher_dec_fn = chacha8_cipher_wrapper
    };
    return &cipher;
}

//
// ChaCha12
//
static const CF_CIPHER *CF_get_chacha12(void) {
    static CF_CIPHER cipher = {
        .id = CF_CHACHA12,
        .ctx_size = sizeof(ll_CHACHA12_CTX),
        .key_ctx_size = 0,
        .block_size = 0,
        .cipher_init_fn = chacha12_init_wrapper,
        .cipher_enc_fn = chacha12_cipher_wrapper,
        .cipher_dec_fn = chacha12_cipher_wrapper
    };
    return &cipher;
}

//
// ChaCha20
//
static const CF_CIPHER *CF_get_chacha20(void) {
    static CF_CIPHER cipher = {
        .id = CF_CHACHA20,
        .ctx_size = sizeof(ll_CHACHA20_CTX),
        .key_ctx_size = 0,
        .block_size = 0,
        .cipher_init_fn = chacha20_init_wrapper,
        .cipher_enc_fn = chacha20_cipher_wrapper,
        .cipher_dec_fn = chacha20_cipher_wrapper
    };
    return &cipher;
}

//
// XChaCha8
//
static const CF_CIPHER *CF_get_xchacha8(void) {
    static CF_CIPHER cipher = {
        .id = CF_XCHACHA8,
        .ctx_size = sizeof(ll_XCHACHA8_CTX),
        .key_ctx_size = 0,
        .block_size = 0,
        .cipher_init_fn = xchacha8_init_wrapper,
        .cipher_enc_fn = xchacha8_cipher_wrapper,
        .cipher_dec_fn = xchacha8_cipher_wrapper
    };
    return &cipher;
}

//
// XChaCha12
//
static const CF_CIPHER *CF_get_xchacha12(void) {
    static CF_CIPHER cipher = {
        .id = CF_XCHACHA12,
        .ctx_size = sizeof(ll_XCHACHA12_CTX),
        .key_ctx_size = 0,
        .block_size = 0,
        .cipher_init_fn = xchacha12_init_wrapper,
        .cipher_enc_fn = xchacha12_cipher_wrapper,
        .cipher_dec_fn = xchacha12_cipher_wrapper
    };
    return &cipher;
}

//
// XChaCha20
//
static const CF_CIPHER *CF_get_xchacha20(void) {
    static CF_CIPHER cipher = {
        .id = CF_XCHACHA20,
        .ctx_size = sizeof(ll_XCHACHA20_CTX),
        .key_ctx_size = 0,
        .block_size = 0,
        .cipher_init_fn = xchacha20_init_wrapper,
        .cipher_enc_fn = xchacha20_cipher_wrapper,
        .cipher_dec_fn = xchacha20_cipher_wrapper
    };
    return &cipher;
}

// Table of all supported Ciphers
static const CF_ALGO_ENTRY cf_Cipher_table[] = {
    { CF_AES_ECB,     (const void* (*)(void))CF_get_aes_ecb    },
    { CF_AES_CBC,     (const void* (*)(void))CF_get_aes_cbc    },
    { CF_AES_OFB,     (const void* (*)(void))CF_get_aes_ofb    },
    { CF_AES_CFB8,    (const void* (*)(void))CF_get_aes_cfb8   },
    { CF_AES_CFB128,  (const void* (*)(void))CF_get_aes_cfb128 },
    { CF_AES_CTR,     (const void* (*)(void))CF_get_aes_ctr    },

    { CF_CHACHA8,     (const void* (*)(void))CF_get_chacha8    },
    { CF_CHACHA12,    (const void* (*)(void))CF_get_chacha12   },
    { CF_CHACHA20,    (const void* (*)(void))CF_get_chacha20   },

    { CF_XCHACHA8,    (const void* (*)(void))CF_get_xchacha8    },
    { CF_XCHACHA12,   (const void* (*)(void))CF_get_xchacha12   },
    { CF_XCHACHA20,   (const void* (*)(void))CF_get_xchacha20   },
};

const CF_CIPHER *CF_Cipher_GetByFlag(uint32_t algo_flag) {
    if (!CF_IS_CIPHER(algo_flag)) 
        return NULL;

    size_t table_len = sizeof(cf_Cipher_table) / sizeof(cf_Cipher_table[0]);
    for (size_t i = 0; i < table_len; i++) {
        if (cf_Cipher_table[i].flag == algo_flag) {
            return (const CF_CIPHER*)cf_Cipher_table[i].getter_fn();
        }
    }
    return NULL;
}

CF_STATUS CF_Cipher_Init(
    CF_CIPHER_CTX *ctx, const CF_CIPHER *cipher, CF_CIPHER_OPTS *opts,
    const uint8_t *key, size_t key_len, CF_CIPHER_OPERATION op) {
    if (!ctx || !cipher || !key)
        return CF_ERR_NULL_PTR;

    if (!CF_IS_CIPHER(cipher->id))
        return CF_ERR_UNSUPPORTED;

    if (opts && opts->magic != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    if (ctx->isHeapAlloc != 0 && ctx->isHeapAlloc != 1)
        return CF_ERR_CTX_UNINITIALIZED;

    if (op != CF_CIPHER_OP_ENCRYPT && op != CF_CIPHER_OP_DECRYPT)
        return CF_ERR_INVALID_PARAM;

    // Fresh cleanup
    CF_Cipher_Reset(ctx);

    ctx->cipher    = cipher;
    ctx->opts      = opts;
    ctx->key       = key;
    ctx->key_len   = key_len;
    ctx->operation = op;

    if (CF_IS_AES(ctx->cipher->id)) {
        if (!CF_IS_AES_KEY_VALID(key_len))
            return CF_ERR_CIPHER_INVALID_KEY_LEN;

        ctx->key_ctx = (void *)SECURE_ALLOC(ctx->cipher->key_ctx_size);
        if (!ctx->key_ctx)
            return CF_ERR_ALLOC_FAILED;

        if (!ll_AES_SetEncryptKey((ll_AES_KEY *)ctx->key_ctx, key, ctx->key_len)) {
            CF_Cipher_Reset(ctx);
            return CF_ERR_CIPHER_KEY_SETUP;
        }
    } else if (CF_IS_CHACHA(ctx->cipher->id)) {
        if (!CF_IS_CHACHA_KEY_VALID(key_len))
            return CF_ERR_CIPHER_INVALID_KEY_LEN;

        // Reject invalid cipher context size
        if (ctx->cipher->ctx_size == 0) 
            return CF_ERR_CTX_CORRUPT;

        ctx->cipher_ctx = (void *)SECURE_ALLOC(ctx->cipher->ctx_size);
        if (!ctx->cipher_ctx)
            return CF_ERR_ALLOC_FAILED;

        // Initialize context
        CF_STATUS st = ctx->cipher->cipher_init_fn(ctx, ctx->opts);
        if (st != CF_SUCCESS) {
            CF_Cipher_Reset(ctx);
            return st;
        }

    } else {
        return CF_ERR_UNSUPPORTED;
    }

    // Bind a per-context "magic" value for integrity checking
    // Detects accidental misuse or corruption of the context
    ctx->magic = CF_CTX_MAGIC ^ (uintptr_t)ctx->cipher;

    return CF_SUCCESS;
}

CF_CIPHER_CTX* CF_Cipher_InitAlloc(
    const CF_CIPHER *cipher, CF_CIPHER_OPTS *opts,
    const uint8_t *key, size_t key_len, 
    CF_CIPHER_OPERATION op, CF_STATUS *status) {
    if (!cipher) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    if (op != CF_CIPHER_OP_ENCRYPT && op != CF_CIPHER_OP_DECRYPT) {
        if (status) *status = CF_ERR_INVALID_PARAM;
        return NULL;
    }

    // Allocate memory for a new cipher context on the heap
    CF_CIPHER_CTX *ctx = (CF_CIPHER_CTX *)SECURE_ALLOC(sizeof(CF_CIPHER_CTX));
    if (!ctx) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Initialize the newly allocated cipher context
    CF_STATUS st = CF_Cipher_Init(ctx, cipher, opts, key, key_len, op);
    if (st != CF_SUCCESS) {
        // Clean up on failure
        SECURE_FREE(ctx, sizeof(CF_CIPHER_CTX));
        if (status) *status = st;
        return NULL;
    }

    // Mark context as heap-allocated for proper cleanup later
    ctx->isHeapAlloc = 1;
    
    if (status) *status = CF_SUCCESS;
    return ctx;
}

CF_STATUS CF_Cipher_Process(CF_CIPHER_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out) {
    if (!ctx || !out)
        return CF_ERR_NULL_PTR;

    // Ensure the cipher or key context and descriptor are initialized
    if (!ctx->cipher || (!ctx->cipher_ctx && !ctx->key_ctx))
        return CF_ERR_CTX_UNINITIALIZED;

    // Verify integrity of the context using the bound "magic" value
    // Detects accidental corruption or misuse of the context
    if ((ctx->magic ^ (uintptr_t)ctx->cipher) != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    /*
     * NOTE: PADDING IS NOT HANDLED YET, AWAITING FOR PADDING MODULE TO BE IMPLEMENTED FIRST.
     */

    if (ctx->operation == CF_CIPHER_OP_ENCRYPT) {
        if (!ctx->cipher->cipher_enc_fn(ctx, in, in_len, out, (const CF_CIPHER_OPTS *)ctx->opts))
            return CF_ERR_CIPHER_ENCRYPT;
    } else if (ctx->operation == CF_CIPHER_OP_DECRYPT) {
        if (!ctx->cipher->cipher_dec_fn(ctx, in, in_len, out, (const CF_CIPHER_OPTS *)ctx->opts))
            return CF_ERR_CIPHER_DECRYPT;
    } else {
        return CF_ERR_CTX_CORRUPT;
    }

    return CF_SUCCESS;
}

CF_STATUS CF_Cipher_Reset(CF_CIPHER_CTX *ctx) {
    if (!ctx)
        return CF_ERR_NULL_PTR;

    if (!ctx->cipher)
        return CF_ERR_CTX_UNINITIALIZED;

    if (ctx->cipher_ctx) {
        if (ctx->cipher->ctx_size == 0)
            return CF_ERR_CTX_CORRUPT;
        SECURE_FREE(ctx->cipher_ctx, ctx->cipher->ctx_size);
    }

    if (ctx->key_ctx) {
        if (ctx->cipher->key_ctx_size == 0)
            return CF_ERR_CTX_CORRUPT;
        SECURE_FREE(ctx->key_ctx, ctx->cipher->key_ctx_size);
    }

    ctx->cipher    = NULL;
    ctx->opts      = NULL;
    ctx->key       = NULL;
    ctx->key_len   = 0;
    ctx->operation = 0;
    ctx->magic     = 0;

    return CF_SUCCESS;
}

CF_STATUS CF_Cipher_Free(CF_CIPHER_CTX **p_ctx) {
    if (!p_ctx || !*p_ctx)
        return CF_ERR_NULL_PTR;

    CF_CIPHER_CTX *ctx = *p_ctx;

    CF_Cipher_Reset(ctx);

    if (ctx->isHeapAlloc) {
        SECURE_ZERO(ctx, sizeof(CF_CIPHER_CTX));
        *p_ctx = NULL;
    }

    return CF_SUCCESS; 
}

FORCE_INLINE CF_STATUS CF_Cipher_EncDec(
    const CF_CIPHER *cipher,
    const uint8_t *key, size_t key_len,
    const uint8_t *in, size_t in_len, uint8_t *out,
    CF_CIPHER_OPTS *opts, CF_CIPHER_OPERATION op) {
    if (!cipher || !key || !out)
        return CF_ERR_NULL_PTR;

    CF_CIPHER_CTX ctx = {0};
    CF_STATUS st = CF_SUCCESS;

    st = CF_Cipher_Init(&ctx, cipher, opts, key, key_len, op);
    if (st != CF_SUCCESS || (ctx.magic ^ (uintptr_t)ctx.cipher) != CF_CTX_MAGIC)
        goto cleanup;

    st = CF_Cipher_Process(&ctx, in, in_len, out);

cleanup:
    CF_Cipher_Reset(&ctx);
    return st;
}

CF_STATUS CF_Cipher_Encrypt(
    const CF_CIPHER *cipher,
    const uint8_t *key, size_t key_len,
    const uint8_t *in, size_t in_len, uint8_t *out,
    CF_CIPHER_OPTS *opts) {
    return CF_Cipher_EncDec(cipher, key, key_len, in, in_len, out, opts, CF_CIPHER_OP_ENCRYPT);
}

CF_STATUS CF_Cipher_Decrypt(
    const CF_CIPHER *cipher,
    const uint8_t *key, size_t key_len,
    const uint8_t *in, size_t in_len, uint8_t *out,
    CF_CIPHER_OPTS *opts) {
    return CF_Cipher_EncDec(cipher, key, key_len, in, in_len, out, opts, CF_CIPHER_OP_DECRYPT);
}

CF_STATUS CF_Cipher_CloneCtx(CF_CIPHER_CTX *dst, const CF_CIPHER_CTX *src) {
    if (!dst || !src)
        return CF_ERR_NULL_PTR;

    // Ensure the cipher descriptor exists
    if (!src->cipher)
        return CF_ERR_CTX_UNINITIALIZED;

    // Verify integrity of the context using the bound "magic" value
    // Detects accidental corruption or misuse of the context
    if ((src->magic ^ (uintptr_t)src->cipher) != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    // Reset the cipher context to a clean state
    CF_Cipher_Reset(dst);

    // Copy metadata (shallow)
    dst->magic     = src->magic;
    dst->cipher    = src->cipher;
    dst->opts      = src->opts;
    dst->key       = src->key;
    dst->key_len   = src->key_len;
    dst->operation = src->operation;

    CF_STATUS st = CF_SUCCESS;

    // Deep copy low-level key context
    if (src->key_ctx) {
        if (src->cipher->key_ctx_size == 0)
            return CF_ERR_CTX_CORRUPT;

        dst->key_ctx = SECURE_ALLOC(src->cipher->key_ctx_size);
        if (!dst->key_ctx) {
            st = CF_ERR_ALLOC_FAILED;
            goto cleanup;
        }

        SECURE_MEMCPY(dst->key_ctx, src->key_ctx, src->cipher->key_ctx_size);
    }

    // Deep copy low-level cipher context
    if (src->cipher_ctx) {
        dst->cipher_ctx = SECURE_ALLOC(src->cipher->ctx_size);
        if (!dst->cipher_ctx) {
            st = CF_ERR_ALLOC_FAILED;
            goto cleanup;
        }

        SECURE_MEMCPY(dst->cipher_ctx, src->cipher_ctx, src->cipher->ctx_size);
    }

    return st;

cleanup:
    // Cleanup partially allocated memory
    if (dst->key_ctx && src->cipher->key_ctx_size)
        SECURE_FREE(dst->key_ctx, src->cipher->key_ctx_size);

    if (dst->cipher_ctx && src->cipher->ctx_size)
        SECURE_FREE(dst->cipher_ctx, src->cipher->ctx_size);

    return st;
}

CF_CIPHER_CTX* CF_Cipher_CloneCtxAlloc(const CF_CIPHER_CTX *src, CF_STATUS *status) {
    if (!src) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    CF_CIPHER_CTX *dst = (CF_CIPHER_CTX *)SECURE_ALLOC(sizeof(CF_CIPHER_CTX));
    if (!dst) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Deep copy contents
    CF_STATUS ret = CF_Cipher_CloneCtx(dst, src);
    if (ret != CF_SUCCESS) {
        if (status) *status = ret;
        CF_Cipher_Free(&dst);
        return NULL;
    }

    // cloned context is heap-allocated
    dst->isHeapAlloc = 1;

    if (status) *status = CF_SUCCESS;
    return dst;
}
