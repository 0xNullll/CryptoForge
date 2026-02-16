/*
 * CryptoForge - cf_aead.c / High-level AEAD Cipher context implementation
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against WyChaProof test vectors. No hardware optimizations. Use with caution.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#include "../../include/cf_api/cf_aead.h"

//
// Wrappers for all hashes
//

// typedef struct _CF_AEAD {
//     uint32_t id;                  // CF_AEAD ID / flag
//     size_t ctx_size;              // low-level context size
//     size_t key_ctx_size;          // low-level expanded key size

//     // Low-level function pointers
//     bool (*aead_init_fn)(CF_AEAD_CTX *ctx);
//     bool (*aead_enc_fn)(const CF_AEAD_CTX *ctx,
//                         const uint8_t *in, size_t in_len,
//                         uint8_t *out);
//     bool (*aead_dec_fn)(const CF_AEAD_CTX *ctx,
//                         const uint8_t *in, size_t in_len,
//                         uint8_t *out);
//     bool (*aead_final_fn)(CF_AEAD_CTX *ctx,
//                           uint8_t *tag, size_t tag_len);
// } CF_AEAD;

// AES-GCM
static bool aes_gcm_init_wrapper(CF_AEAD_CTX *ctx) {
    return ll_AES_GCM_Init((const ll_AES_GCM_CTX *)ctx->aead_ctx, (const ll_AES_KEY *)ctx->key_ctx, ctx->iv, ctx->iv_len, ctx->aad, ctx->aad_len, ctx->operation);
}
static bool aes_gcm_update_wrapper(const CF_AEAD_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out) {
    return ll_AES_GCM_Update((const ll_AES_GCM_CTX *)ctx->aead_ctx, in, in_len, out);
}
static bool aes_gcm_final_wrapper(const CF_AEAD_CTX *ctx, uint8_t *tag, size_t tag_len) {
    return ll_AES_GCM_Final((const ll_AES_GCM_CTX *)ctx->aead_ctx, tag, tag_len);
}

// ChaCha20-Poly1305
static bool chacha20_poly1305_init_wrapper(CF_AEAD_CTX *ctx) {
    return ll_CHACHA20_POLY1305_Init((const ll_CHACHA20_POLY1305_CTX *)ctx->aead_ctx, ctx->key, ctx->key_len, ctx->iv, ctx->aad, ctx->aad_len, ctx->operation);
}
static bool chacha20_poly1305_update_wrapper(const CF_AEAD_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out) {
    return ll_CHACHA20_POLY1305_Update((const ll_CHACHA20_POLY1305_CTX *)ctx->aead_ctx, in, in_len, out);
}
static bool chacha20_poly1305_final_wrapper(const CF_AEAD_CTX *ctx, uint8_t *tag, size_t tag_len) {
    return ll_CHACHA20_POLY1305_Final((const ll_CHACHA20_POLY1305_CTX *)ctx->aead_ctx, tag);
}

// XChaCha20-Poly1305
static bool xchacha20_poly1305_init_wrapper(CF_AEAD_CTX *ctx) {
    return ll_XCHACHA20_POLY1305_Init((const ll_CHACHA20_POLY1305_CTX *)ctx->aead_ctx, ctx->key, ctx->iv, ctx->aad, ctx->aad_len, ctx->operation);
}
static bool xchacha20_poly1305_update_wrapper(const CF_AEAD_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out) {
    return ll_XCHACHA20_POLY1305_Update((const ll_CHACHA20_POLY1305_CTX *)ctx->aead_ctx, in, in_len, out);
}
static bool xchacha20_poly1305_final_wrapper(const CF_AEAD_CTX *ctx, uint8_t *tag, size_t tag_len) {
    return ll_XCHACHA20_POLY1305_Final((const ll_CHACHA20_POLY1305_CTX *)ctx->aead_ctx, tag);
}

//
// XChaCha20-Poly1305
//
// static const CF_AEAD *CF_get_xchacha20_poly1305(void) {
//     static CF_AEAD aead = {
//         .id = CF_XCHACHA20,
//         .ctx_size = sizeof(ll_XCHACHA20_CTX),
//         .key_ctx_size = 0,
//         .block_size = 0,
//         .cipher_init_fn = xchacha20_init_wrapper,
//         .cipher_enc_fn = xchacha20_cipher_wrapper,
//         .cipher_dec_fn = xchacha20_cipher_wrapper
//     };
//     return &cipher;
// }

// Table of all supported AEAD Ciphers
static const CF_ALGO_ENTRY cf_AEAD_table[] = {
    {0, NULL}
    // { CF_AES_ECB,     (const void* (*)(void))CF_get_aes_ecb    },
    // { CF_AES_CBC,     (const void* (*)(void))CF_get_aes_cbc    },
    // { CF_AES_OFB,     (const void* (*)(void))CF_get_aes_ofb    },
    // { CF_AES_CFB8,    (const void* (*)(void))CF_get_aes_cfb8   },
    // { CF_AES_CFB128,  (const void* (*)(void))CF_get_aes_cfb128 },
    // { CF_AES_CTR,     (const void* (*)(void))CF_get_aes_ctr    },

    // { CF_CHACHA8,     (const void* (*)(void))CF_get_chacha8    },
    // { CF_CHACHA12,    (const void* (*)(void))CF_get_chacha12   },
    // { CF_CHACHA20,    (const void* (*)(void))CF_get_chacha20   },

    // { CF_XCHACHA8,    (const void* (*)(void))CF_get_xchacha8    },
    // { CF_XCHACHA12,   (const void* (*)(void))CF_get_xchacha12   }
    // { CF_XCHACHA20,   (const void* (*)(void))CF_get_xchacha20   }
};

const CF_AEAD *CF_AEAD_GetByFlag(uint32_t algo_flag) {
    if (!CF_IS_AEAD(algo_flag)) 
        return NULL;

    size_t table_len = sizeof(cf_AEAD_table) / sizeof(cf_AEAD_table[0]);
    for (size_t i = 0; i < table_len; i++) {
        if (cf_AEAD_table[i].flag == algo_flag) {
            return (const CF_AEAD*)cf_AEAD_table[i].getter_fn();
        }
    }
    return NULL;
}