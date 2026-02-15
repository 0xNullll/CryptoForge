/*
 * CryptoForge - cf_cipher.h / High-level cipher context and utility definitions
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against test vectors. No hardware optimizations. Use with caution.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#ifndef CF_CIPHER_H
#define CF_CIPHER_H

#include "../config/crypto_config.h"
#include "../config/libs.h"

#include "../utils/misc.h"
#include "../utils/mem.h"
#include "../utils/cf_status.h"

#include "cf_defs.h"
#include "cf_flags.h"

#include "../crypto/aes_core.h"
#include "../crypto/ecb_mode.h"
#include "../crypto/cbc_mode.h"
#include "../crypto/cfb_mode.h"
#include "../crypto/ofb_mode.h"
#include "../crypto/ctr_mode.h"
#include "../crypto/chacha_core.h"
#include "../crypto/chacha.h"
#include "../crypto/xchacha_core.h"
#include "../crypto/xchacha.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================
// Cipher descriptor
// ============================
typedef struct _CF_CIPHER {
    uint32_t id;                  // CF_CIPHER ID / flag
    size_t ctx_size;              // low-level context size
    size_t key_ctx_size;          // low-level expanded key size
    size_t block_size;            // cipher block size (0 for stream ciphers)

    // Low-level function pointers
    bool (*cipher_init_fn)(CF_CIPHER_CTX *ctx, CF_CIPHER_OPTS *opts);
    bool (*cipher_enc_fn)(const CF_CIPHER_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out, const CF_CIPHER_OPTS *opts);
    bool (*cipher_dec_fn)(const CF_CIPHER_CTX *ctx, const uint8_t *in, size_t in_len,uint8_t *out, const CF_CIPHER_OPTS *opts);
} CF_CIPHER;

// ============================
// Optional cipher parameters
// ============================
typedef struct _CF_CIPHER_OPTS {
    uint32_t magic;                    // CF_CTX_MAGIC

    uint8_t iv[CF_MAX_CIPHER_IV_SIZE]; // optional IV / nonce
    size_t iv_len;

    // AES/CTR
    uint8_t ctr_block[AES_BLOCK_SIZE]; // 16-byte counter/IV array for AES-CTR

    // ChaCha / XChaCha
    uint32_t chacha_counter;     // 32-bit counter for ChaCha

    uint32_t subflags;           // padding flags

    int isHeapAlloc;
} CF_CIPHER_OPTS;

typedef enum {
    CF_CIPHER_OP_ENCRYPT = 0,
    CF_CIPHER_OP_DECRYPT = 1
} CF_CIPHER_OPERATION;

// ============================
// High-level cipher context
// ============================
typedef struct _CF_CIPHER_CTX {
    uint64_t magic;                 // CF_CTX_MAGIC ^ (uintptr_t)cipher

    const CF_CIPHER *cipher;        // selected algorithm
    CF_CIPHER_OPTS *opts;

    void *cipher_ctx;               // low-level cipher state
    void *key_ctx;                  // internal expanded key

    const uint8_t *key;             // user-supplied raw key
    size_t key_len;

    CF_CIPHER_OPERATION operation;  // encrypt or decrypt
    int isHeapAlloc;
} CF_CIPHER_CTX;

// ============================
// Algorithm selection
// ============================
CF_API const CF_CIPHER *CF_Cipher_GetByFlag(uint32_t cipher_flag);

// ============================
// Context initialization & cleanup
// ============================
CF_API CF_STATUS CF_Cipher_Init(CF_CIPHER_CTX *ctx, const CF_CIPHER *cipher, CF_CIPHER_OPTS *opts,
                                const uint8_t *key, size_t key_len, CF_CIPHER_OPERATION op);

CF_API CF_CIPHER_CTX* CF_Cipher_InitAlloc(const CF_CIPHER *cipher, CF_CIPHER_OPTS *opts,
                                          const uint8_t *key, size_t key_len, 
                                          CF_CIPHER_OPERATION op, CF_STATUS *status);

/*
* NOTE: PADDING IS NOT HANDLED YET, AWAITING FOR PADDING MODULE TO BE IMPLEMENTED FIRST.
*/
CF_API CF_STATUS CF_Cipher_Process(CF_CIPHER_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out);

CF_API CF_STATUS CF_Cipher_Reset(CF_CIPHER_CTX *ctx);
CF_API CF_STATUS CF_Cipher_Free(CF_CIPHER_CTX **p_ctx);

// ============================
// One-shot encryption/decryption
// ============================
CF_API CF_STATUS CF_Cipher_Encrypt(const CF_CIPHER *cipher,
                                   const uint8_t *key, size_t key_len,
                                   const uint8_t *in, size_t in_len, uint8_t *out,
                                   CF_CIPHER_OPTS *opts);

CF_API CF_STATUS CF_Cipher_Decrypt(const CF_CIPHER *cipher,
                                   const uint8_t *key, size_t key_len,
                                   const uint8_t *in, size_t in_len, uint8_t *out,
                                   CF_CIPHER_OPTS *opts);

// ============================
// Cloning
// ============================
CF_API CF_STATUS CF_Cipher_CloneCtx(CF_CIPHER_CTX *dst, const CF_CIPHER_CTX *src);
CF_API CF_CIPHER_CTX* CF_Cipher_CloneCtxAlloc(const CF_CIPHER_CTX *src, CF_STATUS *status);

// ============================
// helper / utilities
// ============================
CF_API CF_STATUS CF_Cipher_ValidateCtx(const CF_CIPHER_CTX *ctx);
CF_API const char* CF_Cipher_GetName(const CF_CIPHER *cipher);
CF_API const char* CF_Cipher_GetFullName(const CF_CIPHER_CTX *ctx);
CF_API bool CF_Cipher_IsValidKeyLength(const CF_CIPHER *cipher, size_t key_len);
CF_API const size_t* CF_Cipher_GetValidKeySizes(const CF_CIPHER *cipher, size_t *count);
CF_API size_t CF_Cipher_GetBlockSize(const CF_CIPHER_CTX *ctx);
CF_API size_t CF_Cipher_GetOutputLength(const CF_CIPHER_CTX *ctx, size_t input_len);

// ============================
// Optional parameters init / cleanup
// ============================

/*
 * NOTE: INVALID SUBFLAGS ARE NOT HANDLED YET
*/
CF_API CF_STATUS CF_CipherOpts_Init(CF_CIPHER_OPTS *opts,
                                    const uint8_t *iv, size_t iv_len,
                                    const uint8_t ctr_block[AES_BLOCK_SIZE], // optional, can be NULL
                                    uint32_t chacha_counter,                 // optional, pass 0 for default
                                    uint32_t subflags);                      // optional, for padding

CF_API CF_CIPHER_OPTS* CF_CipherOpts_InitAlloc(const uint8_t *iv, size_t iv_len,
                                               const uint8_t ctr_block[AES_BLOCK_SIZE], // optional, can be NULL
                                               uint32_t chacha_counter,                 // optional, pass 0 for default
                                               uint32_t subflags,                       // optional, for padding
                                               CF_STATUS *status);

CF_API CF_STATUS CF_CipherOpts_Reset(CF_CIPHER_OPTS *opts);
CF_API CF_STATUS CF_CipherOpts_Free(CF_CIPHER_OPTS **p_opts);

CF_API CF_STATUS CF_CipherOpts_CloneCtx(CF_CIPHER_OPTS *dst, const CF_CIPHER_OPTS *src);
CF_API CF_CIPHER_OPTS* CF_CipherOpts_CloneCtxAlloc(const CF_CIPHER_OPTS *src, CF_STATUS *status);

#ifdef __cplusplus
}
#endif

#endif // CF_CIPHER_H