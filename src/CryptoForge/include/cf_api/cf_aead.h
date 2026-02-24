/*
 * CryptoForge - cf_aead.h / High-level AEAD cipher context and utility definitions
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

#ifndef CF_AEAD_H
#define CF_AEAD_H

#include "../config/crypto_config.h"
#include "../config/libs.h"

#include "../utils/misc.h"
#include "../utils/mem.h"
#include "../utils/cf_status.h"

#include "cf_defs.h"
#include "cf_flags.h"

#include "../crypto/aes_core.h"
#include "../crypto/aes_gcm.h"
#include "../crypto/chacha20_poly1305.h"
#include "../crypto/xchacha20_poly1305.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================
// AEAD descriptor
// ============================
typedef struct _CF_AEAD {
    uint32_t id;                  // CF_AEAD ID / flag
    size_t ctx_size;              // low-level context size
    size_t key_ctx_size;          // low-level expanded key size

    // Low-level function pointers
    bool (*aead_init_fn)(const CF_AEAD_CTX *ctx);
    bool (*aead_update_fn)(const CF_AEAD_CTX *ctx,
                        const uint8_t *in, size_t in_len,
                        uint8_t *out);
    bool (*aead_final_fn)(const CF_AEAD_CTX *ctx,
                          uint8_t *tag, size_t tag_len);
} CF_AEAD;

// ============================
// High-level AEAD context
// ============================
typedef struct _CF_AEAD_CTX {
    uint64_t magic;                 // CF_CTX_MAGIC ^ (uintptr_t)aead

    const CF_AEAD *aead;            // selected AEAD algorithm

    void *aead_ctx;                 // low-level AEAD state
    void *key_ctx;                  // internal expanded key

    const uint8_t *key;             // user-supplied raw key
    size_t key_len;

    const uint8_t *iv;              // initialization vector / nonce
    size_t iv_len;

    const uint8_t *aad;             // additional authenticated data
    size_t aad_len;

    uint64_t total_data_len;        // keep count of the inputed data length

    CF_OPERATION operation;    // encrypt or decrypt
    int isHeapAlloc;
} CF_AEAD_CTX;

// ============================
// Algorithm selection
// ============================
CF_API const CF_AEAD *CF_AEAD_GetByFlag(uint32_t algo_flag);

// ============================
// Context initialization & cleanup
// ============================
CF_API CF_STATUS CF_AEAD_Init(CF_AEAD_CTX *ctx, const CF_AEAD *aead,
                              const uint8_t *key, size_t key_len,
                              const uint8_t *iv, size_t iv_len,
                              const uint8_t *aad, size_t aad_len,
                              CF_OPERATION op);

CF_API CF_AEAD_CTX* CF_AEAD_InitAlloc(const CF_AEAD *aead,
                                      const uint8_t *key, size_t key_len,
                                      const uint8_t *iv, size_t iv_len,
                                      const uint8_t *aad, size_t aad_len,
                                      CF_OPERATION op, CF_STATUS *status);

CF_API CF_STATUS CF_AEAD_Update(CF_AEAD_CTX *ctx,
                                const uint8_t *in, size_t in_len,
                                uint8_t *out, size_t *out_len);

CF_API CF_STATUS CF_AEAD_Final(CF_AEAD_CTX *ctx,
                               uint8_t *tag, size_t tag_len);

CF_API CF_STATUS CF_AEAD_Reset(CF_AEAD_CTX *ctx);
CF_API CF_STATUS CF_AEAD_Free(CF_AEAD_CTX **p_ctx);

// ============================
// One-shot AEAD convenience functions
// ============================
CF_API CF_STATUS CF_AEAD_Encrypt(const CF_AEAD *aead,
                                 const uint8_t *key, size_t key_len,
                                 const uint8_t *iv, size_t iv_len,
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *in, size_t in_len,
                                 uint8_t *out, size_t *out_len,
                                 uint8_t *tag, size_t tag_len);

CF_API CF_STATUS CF_AEAD_Decrypt(const CF_AEAD *aead,
                                 const uint8_t *key, size_t key_len,
                                 const uint8_t *iv, size_t iv_len,
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *in, size_t in_len,
                                 uint8_t *out, size_t *out_len,
                                 uint8_t *tag, size_t tag_len);

// ============================
// One-shot AEAD convenience functions (ciphertext + tag combined)
// ============================
CF_API CF_STATUS CF_AEAD_EncryptAppendTag(
    const CF_AEAD *aead,
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *in, size_t in_len,
    uint8_t *out, size_t *out_len);  // out_len = ciphertext_len + fixed_tag_len

CF_API CF_STATUS CF_AEAD_DecryptAppendTag(
    const CF_AEAD *aead,
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *in, size_t in_len, // in_len = ciphertext_len + fixed_tag_len
    uint8_t *out, size_t *out_len);

// ============================
// Cloning
// ============================
CF_API CF_STATUS CF_AEAD_CloneCtx(CF_AEAD_CTX *dst, const CF_AEAD_CTX *src);
CF_API CF_AEAD_CTX* CF_AEAD_CloneCtxAlloc(const CF_AEAD_CTX *src, CF_STATUS *status);

// ============================
// Helper / utilities
// ============================
CF_API CF_STATUS CF_AEAD_ValidateCtx(const CF_AEAD_CTX *ctx);
CF_API const char* CF_AEAD_GetName(const CF_AEAD *aead);
CF_API const char* CF_AEAD_GetFullName(const CF_AEAD_CTX *ctx);
CF_API bool CF_AEAD_IsValidKeyLength(const CF_AEAD *aead, size_t key_len);
CF_API bool CF_AEAD_IsValidTagLength(const CF_AEAD *aead, size_t tag_len);
CF_API const size_t* CF_AEAD_GetValidKeySizes(const CF_AEAD *aead, size_t *count);
CF_API const size_t* CF_AEAD_GetValidTagSizes(const CF_AEAD *aead, size_t *count);
CF_API size_t CF_AEAD_GetMaxTagSize(const CF_AEAD *aead);

#ifdef __cplusplus
}
#endif

#endif // CF_AEAD_H