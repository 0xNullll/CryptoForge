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
