/*
 * CryptoForge - aes_gcm.h / AES-GCM Interface
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

#ifndef AES_GCM_H
#define AES_GCM_H

#include "../utils/mem.h"
#include "../utils/misc.h"
#include "../utils/bitops.h"

#include "../config/libs.h"

#include "aes_core.h"

#ifdef __cplusplus
extern "C" {
#endif

//
// AES-GCM main input validation
// - Key, IV, output, and tag must be non-NULL
// - IV length >= 12 bytes
// - Tag size within valid range
// - Input and AAD lengths within NIST limits
// - Prevent NULL pointers for non-zero inputs
//

#define AES_GCM_MAX_DATA_LEN      ((U64(1) << 36) - U64(32)) // ~64 GiB (2^36 - 32 bytes)
#define AES_GCM_AAD_MAX_DATA_LEN  ((U64(1) << 61) - U64(1))  // ~2 EiB (2^61 - 1 bytes)

/* Recommended IV size (per NIST SP 800-38D) */
#define AES_GCM_IV_MIN 12

#define AES_GCM_TAG_32_SIZE   4    // 32-bit tag
#define AES_GCM_TAG_64_SIZE   8    // 64-bit tag
#define AES_GCM_TAG_96_SIZE  12    // 96-bit tag (recommended default)
#define AES_GCM_TAG_128_SIZE 16    // 128-bit tag (maximum)
#define AES_GCM_TAG_SIZE_DEFAULT AES_GCM_TAG_96_SIZE  // default tag size

// macro to check if a tag length is valid
#define IS_VALID_GCM_TAG_SIZE(len) \
    ((len) == AES_GCM_TAG_32_SIZE  || \
     (len) == AES_GCM_TAG_64_SIZE  || \
     (len) == AES_GCM_TAG_96_SIZE || \
     (len) == AES_GCM_TAG_128_SIZE)

// ============================================================================
// Internal low-level functions exposed here solely for GMAC to use internally.
// These are not meant for general public API usage.
// ============================================================================
void ll_gcm_mult(uint8_t Z[AES_BLOCK_SIZE],
            const uint8_t X[AES_BLOCK_SIZE],
            const uint8_t Y[AES_BLOCK_SIZE]);

void ll_GHASH_Process(
    const uint8_t H[AES_BLOCK_SIZE],
    const uint8_t *in, size_t in_len,
    uint8_t out[AES_BLOCK_SIZE]);

bool ll_AES_GCTR_Process(const ll_AES_KEY *key, uint8_t ICB[AES_BLOCK_SIZE], const uint8_t *X, size_t X_len, uint8_t *Y);

typedef struct {
    const ll_AES_KEY *key;       // AES key
    uint8_t H[AES_BLOCK_SIZE];   // GHASH subkey
    uint8_t J0[AES_BLOCK_SIZE];  // initial counter block
    uint8_t ctr[AES_BLOCK_SIZE]; // current counter block for GCTR
    uint8_t X[AES_BLOCK_SIZE];   // GHASH accumulator
    size_t aad_len;              // total AAD length
    size_t data_len;             // total ciphertext/plaintext length
    int isEncrypt;               // 1 = encrypting, 0 = decrypting
} ll_AES_GCM_CTX;

bool ll_AES_GCM_Init(ll_AES_GCM_CTX *ctx,
                     const ll_AES_KEY *key,
                     const uint8_t *iv, size_t iv_len,
                     const uint8_t *aad, size_t aad_len, bool encrypt);

bool ll_AES_GCM_Update(ll_AES_GCM_CTX *ctx,
                            const uint8_t *in, size_t in_len,
                            uint8_t *out);

bool ll_AES_GCM_Final(ll_AES_GCM_CTX *ctx, uint8_t *tag, size_t tag_len);

#ifdef __cplusplus
}
#endif

#endif // AES_GCM_H