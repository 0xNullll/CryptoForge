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
    const uint8_t *key, size_t key_len, CF_OPERATION op) {
    if (!ctx || !cipher || !key)
        return CF_ERR_NULL_PTR;

   // Validate that the cipher type is recognized
    if (!CF_IS_CIPHER(cipher->id))
        return CF_ERR_UNSUPPORTED;

    // Validate options context if provided
    if (opts && opts->magic != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    // Validate heap allocation flag
    if (ctx->isHeapAlloc != 0 && ctx->isHeapAlloc != 1)
        return CF_ERR_CTX_UNINITIALIZED;

    // Ensure operation is either encryption or decryption
    if (op != CF_OP_ENCRYPT && op != CF_OP_DECRYPT)
        return CF_ERR_INVALID_PARAM;

    // Reset context to a clean state
    CF_Cipher_Reset(ctx);

    // Store core context parameters
    ctx->cipher    = cipher;
    ctx->opts      = opts;
    ctx->key       = key;
    ctx->key_len   = key_len;
    ctx->operation = op;

    // AES-specific initialization
    if (CF_IS_AES(ctx->cipher->id)) {

        // Check AES key length
        if (!CF_IS_AES_KEY_VALID(key_len))
            return CF_ERR_CIPHER_INVALID_KEY_LEN;

        // Allocate memory for AES key schedule
        ctx->key_ctx = (void *)SECURE_ALLOC(ctx->cipher->key_ctx_size);
        if (!ctx->key_ctx)
            return CF_ERR_ALLOC_FAILED;

        // Initialize AES key schedule
        if (!ll_AES_SetEncryptKey((ll_AES_KEY *)ctx->key_ctx, key, key_len)) {
            CF_Cipher_Reset(ctx);
            return CF_ERR_CIPHER_KEY_SETUP;
        }

    } 
    // ChaCha-specific initialization
    else if (CF_IS_CHACHA(ctx->cipher->id)) {

        // Check ChaCha key length
        if (!CF_IS_CHACHA_KEY_VALID(key_len))
            return CF_ERR_CIPHER_INVALID_KEY_LEN;

        // Reject invalid cipher context size
        if (ctx->cipher->ctx_size == 0) 
            return CF_ERR_CTX_CORRUPT;

        // Allocate memory for ChaCha context
        ctx->cipher_ctx = (void *)SECURE_ALLOC(ctx->cipher->ctx_size);
        if (!ctx->cipher_ctx)
            return CF_ERR_ALLOC_FAILED;

        // Initialize ChaCha low-level context
        bool ok = ctx->cipher->cipher_init_fn(ctx, ctx->opts);
        if (ok != true) {
            CF_Cipher_Reset(ctx);
            return CF_ERR_CTX_CORRUPT;
        }

    } else {
        // Unsupported cipher type
        return CF_ERR_UNSUPPORTED;
    }

    // Bind magic value for context integrity checking
    // Detects accidental misuse or memory corruption
    ctx->magic = CF_CTX_MAGIC ^ (uintptr_t)ctx->cipher;

    return CF_SUCCESS;
}

CF_CIPHER_CTX* CF_Cipher_InitAlloc(
    const CF_CIPHER *cipher, CF_CIPHER_OPTS *opts,
    const uint8_t *key, size_t key_len, 
    CF_OPERATION op, CF_STATUS *status) {
    if (!cipher) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    // Validate operation mode
    if (op != CF_OP_ENCRYPT && op != CF_OP_DECRYPT) {
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
        // Reset and free memory if initialization failed
        CF_Cipher_Reset(ctx);
        SECURE_FREE(ctx, sizeof(CF_CIPHER_CTX));
        if (status) *status = st;
        return NULL;
    }

    // Mark context as heap-allocated for proper cleanup later
    ctx->isHeapAlloc = 1;

    // Return success status to caller
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

    size_t block = ctx->cipher->block_size;

    // Stream cipher: block_size = 0, no padding required
    if (block == 0) {
        if (ctx->operation == CF_OP_ENCRYPT) {
            if (!ctx->cipher->cipher_enc_fn(ctx, in, in_len, out, ctx->opts))
                return CF_ERR_CIPHER_ENCRYPT;
        } else if (ctx->operation == CF_OP_DECRYPT) {
            if (!ctx->cipher->cipher_dec_fn(ctx, in, in_len, out, ctx->opts))
                return CF_ERR_CIPHER_DECRYPT;
        } else {
            return CF_ERR_CTX_CORRUPT;
        }
        // At this point, all input has been processed correctly and no further
        // block padding or remainder handling is needed.
        return CF_SUCCESS;
    }

    // Block cipher: Compute remainder and full block lengths
    size_t remainder_len = in_len % block;
    size_t full_blocks_len = in_len - remainder_len;

    // Phase 1: process full blocks
    if (full_blocks_len > 0) {
        if (ctx->operation == CF_OP_ENCRYPT) {
            if (!ctx->cipher->cipher_enc_fn(ctx, in, full_blocks_len, out, ctx->opts))
                return CF_ERR_CIPHER_ENCRYPT;
        } else if (ctx->operation == CF_OP_DECRYPT) {
            if (!ctx->cipher->cipher_dec_fn(ctx, in, full_blocks_len, out, ctx->opts))
                return CF_ERR_CIPHER_DECRYPT;
        } else {
            return CF_ERR_CTX_CORRUPT;
        }
    }

    // Phase 2: handle final block (with padding if needed)
    if (remainder_len > 0 && ctx->operation == CF_OP_ENCRYPT) {
        if (!ctx->opts)
            return CF_ERR_CTX_OPTS_UNINITIALIZED;

        uint8_t pad_block[CF_CIPHER_MAX_BLOCK_SIZE] = {0}; // generic max block size
        size_t data_len = remainder_len;

        // Copy remainder into pad buffer (for both encrypt & decrypt)
        if (remainder_len > 0)
            SECURE_MEMCPY(pad_block, in + full_blocks_len, remainder_len);

        CF_STATUS st = CF_SUCCESS;

        if (ctx->operation == CF_OP_ENCRYPT) {
            // Apply padding to final block
            st = CF_Pad_Apply(pad_block, sizeof(pad_block), remainder_len, block, ctx->opts->subflags);
            if (st != CF_SUCCESS) {
                SECURE_ZERO(pad_block, sizeof(pad_block));
                return st;
            }

            // Encrypt padded block
            if (!ctx->cipher->cipher_enc_fn(ctx, pad_block, block, out + full_blocks_len, ctx->opts)) {
                SECURE_ZERO(pad_block, sizeof(pad_block));
                return CF_ERR_CIPHER_ENCRYPT;
            }
        } else if (ctx->operation == CF_OP_DECRYPT) {
            // Decrypt final block first
            if (!ctx->cipher->cipher_dec_fn(ctx, pad_block, block, pad_block, ctx->opts)) {
                SECURE_ZERO(pad_block, sizeof(pad_block));
                return CF_ERR_CIPHER_DECRYPT;
            }

            // Remove padding
            st = CF_Pad_Remove(pad_block, sizeof(pad_block), &data_len, block, ctx->opts->subflags);
            if (st != CF_SUCCESS) {
                SECURE_ZERO(pad_block, sizeof(pad_block));
                return st;
            }

            // Copy unpadded plaintext to output
            SECURE_MEMCPY(out + full_blocks_len, pad_block, data_len);
        }

        SECURE_ZERO(pad_block, sizeof(pad_block));
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

static FORCE_INLINE CF_STATUS CF_Cipher_EncDec(
    const CF_CIPHER *cipher,
    const uint8_t *key, size_t key_len,
    const uint8_t *in, size_t in_len, uint8_t *out,
    CF_CIPHER_OPTS *opts, CF_OPERATION op) {
    if (!cipher || !key || !out)
        return CF_ERR_NULL_PTR;

    // Stack-allocated cipher context for one-shot operation
    CF_CIPHER_CTX ctx = {0};
    CF_STATUS st = CF_SUCCESS;

    // Initialize cipher context with provided key, options, and operation
    st = CF_Cipher_Init(&ctx, cipher, opts, key, key_len, op);

    // Verify initialization succeeded and context integrity is intact
    // The magic check detects accidental corruption or misuse
    if (st != CF_SUCCESS || (ctx.magic ^ (uintptr_t)ctx.cipher) != CF_CTX_MAGIC)
        goto cleanup;

    // Process input buffer (encrypt or decrypt depending on 'op')
    // Output is written to 'out'
    st = CF_Cipher_Process(&ctx, in, in_len, out);

cleanup:
    // Securely clear context regardless of success or failure
    CF_Cipher_Reset(&ctx);

    return st;
}

CF_STATUS CF_Cipher_Encrypt(
    const CF_CIPHER *cipher,
    const uint8_t *key, size_t key_len,
    const uint8_t *in, size_t in_len, uint8_t *out,
    CF_CIPHER_OPTS *opts) {
    return CF_Cipher_EncDec(cipher, key, key_len, in, in_len, out, opts, CF_OP_ENCRYPT);
}

CF_STATUS CF_Cipher_Decrypt(
    const CF_CIPHER *cipher,
    const uint8_t *key, size_t key_len,
    const uint8_t *in, size_t in_len, uint8_t *out,
    CF_CIPHER_OPTS *opts) {
    return CF_Cipher_EncDec(cipher, key, key_len, in, in_len, out, opts, CF_OP_DECRYPT);
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

CF_STATUS CF_Cipher_ValidateCtx(const CF_CIPHER_CTX *ctx) {
    if (!ctx)
        return CF_ERR_NULL_PTR;

    // Verify context integrity using the bound magic value
    // Detects accidental corruption or misuse of the encoder context
    if ((ctx->magic ^ (uintptr_t)ctx->cipher) != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    return CF_SUCCESS;
}

const char* CF_Cipher_GetName(const CF_CIPHER *cipher) {
    if (!cipher)
        return "NULL";

    switch (cipher->id) {
        case CF_AES_ECB:    return "AES-ECB";
        case CF_AES_CBC:    return "AES-CBC";
        case CF_AES_OFB:    return "AES-OFB";
        case CF_AES_CFB8:   return "AES-CFB8";
        case CF_AES_CFB128: return "AES-CFB128";

        case CF_CHACHA8:    return "ChaCha8";
        case CF_CHACHA12:   return "ChaCha12";
        case CF_CHACHA20:   return "ChaCha20";
        case CF_XCHACHA8:   return "XChaCha8";
        case CF_XCHACHA12:  return "XChaCha12";
        case CF_XCHACHA20:  return "XChaCha20";
        
        default:            return "UNKNOWN-CIPHER";
    }
}

const char* CF_Cipher_GetFullName(const CF_CIPHER_CTX *ctx) {
    if (!ctx || !ctx->cipher)
        return "NULL";

    switch (ctx->key_len) {
        case CF_KEY_128_SIZE:
            switch (ctx->cipher->id) {
                case CF_AES_ECB:    return "AES-128-ECB";
                case CF_AES_CBC:    return "AES-128-CBC";
                case CF_AES_OFB:    return "AES-128-OFB";
                case CF_AES_CFB8:   return "AES-128-CFB8";
                case CF_AES_CFB128: return "AES-128-CFB128";
                case CF_AES_CTR:    return "AES-192-CTR";

                case CF_CHACHA8:    return "ChaCha8-128";
                case CF_CHACHA12:   return "ChaCha12-128";
                case CF_CHACHA20:   return "ChaCha20-128";

                default:            return "UNKNOWN-CIPHER-128";
            }

        case CF_KEY_192_SIZE:
            switch (ctx->cipher->id) {
                case CF_AES_ECB:    return "AES-192-ECB";
                case CF_AES_CBC:    return "AES-192-CBC";
                case CF_AES_OFB:    return "AES-192-OFB";
                case CF_AES_CFB8:   return "AES-192-CFB8";
                case CF_AES_CFB128: return "AES-192-CFB128";
                case CF_AES_CTR:    return "AES-192-CTR";

                default:            return "UNKNOWN-CIPHER-192";
            }

        case CF_KEY_256_SIZE:
            switch (ctx->cipher->id) {
                case CF_AES_ECB:    return "AES-256-ECB";
                case CF_AES_CBC:    return "AES-256-CBC";
                case CF_AES_CFB8:   return "AES-256-CFB8";
                case CF_AES_CFB128: return "AES-256-CFB128";
                case CF_AES_OFB:    return "AES-256-OFB";
                case CF_AES_CTR:    return "AES-192-CTR";

                case CF_CHACHA8:    return "ChaCha8-256";
                case CF_CHACHA12:   return "ChaCha12-256";
                case CF_CHACHA20:   return "ChaCha20-256";
                case CF_XCHACHA8:   return "XChaCha8-256";
                case CF_XCHACHA12:  return "XChaCha12-256";
                case CF_XCHACHA20:  return "XChaCha20-256";

                default: 
                    return "UNKNOWN-CIPHER-256";
            }

            default: 
                return "UNKNOWN-CIPHER";
    }
}

 bool CF_Cipher_IsValidKeyLength(const CF_CIPHER *cipher, size_t key_len) {
    if (!cipher)
        return false;

    if (CF_IS_AES(cipher->id)) {
       if (CF_IS_AES_KEY_VALID(key_len))
        return true;
    }
    else if (CF_IS_CHACHA(cipher->id)) {
       if (CF_IS_CHACHA_KEY_VALID(key_len))
        return true;
    }

    return false;
}

const size_t* CF_Cipher_GetValidKeySizes(const CF_CIPHER *cipher, size_t *count) {
    if (!cipher || !count)
        return NULL;

    static const size_t aes_sizes[3] = {CF_KEY_128_SIZE, CF_KEY_192_SIZE, CF_KEY_256_SIZE};
    static const size_t chacha_sizes[2] = {CF_KEY_128_SIZE, CF_KEY_256_SIZE};

    if (CF_IS_AES(cipher->id)) {
        *count = 3;
        return aes_sizes;
    } else if (CF_IS_CHACHA(cipher->id)) {
        *count = 2;
        return chacha_sizes;
    }

    *count = 0;
    return NULL;
}

size_t CF_Cipher_GetBlockSize(const CF_CIPHER_CTX *ctx) {
    return ctx ? (ctx->cipher ? ctx->cipher->block_size : 0) : 0;
}

size_t CF_Cipher_GetOutputLength(const CF_CIPHER_CTX *ctx, size_t in_len) {
    if (!ctx || !ctx->cipher || in_len == 0)
        return 0;

    size_t block = ctx->cipher->block_size;

    if (block == 0) // stream cipher, no padding
        return in_len;

    // Round up to next multiple of block size
    size_t rem = in_len % block;
    if (rem == 0)
        return in_len; // already aligned
    return in_len + (block - rem); // pad to next block
}

CF_STATUS CF_CipherOpts_Init(
    CF_CIPHER_OPTS *opts,
    const uint8_t *iv, size_t iv_len,
    const uint8_t ctr_block[AES_BLOCK_SIZE],
    uint32_t chacha_counter,
    uint32_t subflags) {
    if (!opts)
        return CF_ERR_NULL_PTR;

    if (iv_len > CF_MAX_CIPHER_IV_SIZE)
        return CF_ERR_INVALID_LEN;

    //
    // NOTE: invalid subflags are not handled yet
    //

    CF_CipherOpts_Reset(opts);

    // Shallow copy (caller manages lifetime)
    opts->chacha_counter = chacha_counter;
    opts->subflags       = subflags;

    // Deep copy of IV
    if (iv && iv_len > 0) {
        SECURE_MEMCPY(opts->iv, iv, iv_len);
        opts->iv_len = iv_len;
    }
    
    // Deep copy of AES Counter
    if (ctr_block) {
        SECURE_MEMCPY(opts->ctr_block, ctr_block, sizeof(opts->ctr_block));
    }

    opts->magic = CF_CTX_MAGIC;

    return CF_SUCCESS;
}

CF_CIPHER_OPTS* CF_CipherOpts_InitAlloc(
    const uint8_t *iv, size_t iv_len,
    const uint8_t ctr_block[AES_BLOCK_SIZE], // optional, can be NULL
    uint32_t chacha_counter,                 // optional, pass 0 for default
    uint32_t subflags,                       // optional, for padding
    CF_STATUS *status) {
    if (iv_len > CF_MAX_CIPHER_IV_SIZE) {
        if (status) *status = CF_ERR_INVALID_LEN;
        return NULL;
    }

    CF_CIPHER_OPTS *opts = (CF_CIPHER_OPTS *)SECURE_ALLOC(sizeof(CF_CIPHER_OPTS));
    if (!opts) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    CF_STATUS st = CF_CipherOpts_Init(opts, iv, iv_len, ctr_block, chacha_counter, subflags);
    if (st != CF_SUCCESS) {
        if (status) *status = st;
        // Clean up on failure
        CF_CipherOpts_Free(&opts);
        return NULL;
    }

    opts->isHeapAlloc = 1;
    if (status) *status = CF_SUCCESS;
    return opts;
}

CF_STATUS CF_CipherOpts_Reset(CF_CIPHER_OPTS *opts) {
    if (opts)
        return CF_ERR_NULL_PTR;

    SECURE_ZERO(opts->iv, sizeof(opts->iv));
    SECURE_ZERO(opts->ctr_block, sizeof(opts->ctr_block));

    opts->chacha_counter = 0;
    opts->iv_len         = 0;
    opts->subflags       = 0;
    opts->magic          = 0;

    return CF_SUCCESS;;
}

CF_STATUS CF_CipherOpts_Free(CF_CIPHER_OPTS **p_opts) {
    if (!p_opts || !*p_opts)
        return CF_ERR_NULL_PTR;

    CF_CIPHER_OPTS *ctx = *p_opts;

    CF_CipherOpts_Reset(ctx);

    if (ctx->isHeapAlloc) {
        SECURE_ZERO(ctx, sizeof(CF_CIPHER_OPTS));
    }

    return CF_SUCCESS;
}
CF_STATUS CF_CipherOpts_CloneCtx(CF_CIPHER_OPTS *dst, const CF_CIPHER_OPTS *src) {
    if (!dst || !src)
        return CF_ERR_NULL_PTR;

    if (src->magic != CF_CTX_MAGIC)
        return CF_ERR_CTX_CORRUPT;

    // Start with a clean slate
    CF_CipherOpts_Reset(dst);

    // Deep copy IV
    if (src->iv_len != 0) {
        SECURE_MEMCPY(dst->iv, src->iv, sizeof(dst->iv));
        dst->iv_len = src->iv_len;
    }

    // Deep copy of AES Counter
    SECURE_MEMCPY(dst->ctr_block, src->ctr_block, sizeof(dst->ctr_block));

    dst->chacha_counter = src->chacha_counter;
    dst->subflags       = src->subflags;
    dst->magic          = src->magic;
    dst->isHeapAlloc    = 0;

    return CF_SUCCESS;
}

CF_CIPHER_OPTS* CF_CipherOpts_CloneCtxAlloc(const CF_CIPHER_OPTS *src, CF_STATUS *status) {
    if (!src) {
        if (status) *status = CF_ERR_NULL_PTR;
        return NULL;
    }

    CF_CIPHER_OPTS *dst = (CF_CIPHER_OPTS *)SECURE_ALLOC(sizeof(CF_CIPHER_OPTS));
    if (!dst) {
        if (status) *status = CF_ERR_ALLOC_FAILED;
        return NULL;
    }

    // Deep copy contents
    CF_STATUS ret = CF_CipherOpts_CloneCtx(dst, src);
    if (ret != CF_SUCCESS) {
        if (status) *status = ret;
        CF_CipherOpts_Free(&dst);
        return NULL;
    }

    // cloned context is heap-allocated
    dst->isHeapAlloc = 1;

    if (status) *status = CF_SUCCESS;
    return dst;
}