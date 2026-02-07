/*
 * CryptoForge - chacha.h / ChaCha Variants Interface
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License in the file LICENSE in the
 * source distribution or at:
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * This software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
 * OR CONDITIONS OF ANY KIND, either express or implied. See the License
 * for the specific language governing permissions and limitations under
 * the License.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#ifndef CHACHA_H
#define CHACHA_H

#include "../utils/mem.h"
#include "../utils/misc.h"
#include "../utils/bitops.h"
#include "../utils/cf_status.h"
#include "../config/libs.h"
#include "chacha_core.h"
#include "poly1305.h"

#ifdef __cplusplus
extern "C" {
#endif

// ======================================
// ChaCha Variants / Modes
// ======================================

// ChaCha8 (8 rounds)
#define CHACHA8_ROUNDS 8
typedef ll_CHACHA_CTX ll_CHACHA8_CTX;

bool ll_CHACHA8_init(ll_CHACHA8_CTX *ctx,
                     const uint8_t *key, size_t key_len,
                     const uint8_t iv[CHACHA_IV_SIZE],
                     uint32_t counter);

bool ll_CHACHA8_Cipher(ll_CHACHA8_CTX *ctx,
                       const uint8_t *in, size_t in_len,
                       uint8_t *out);

// ChaCha12 (12 rounds)
#define CHACHA12_ROUNDS 12
typedef ll_CHACHA_CTX ll_CHACHA12_CTX;

bool ll_CHACHA12_init(ll_CHACHA12_CTX *ctx,
                      const uint8_t *key, size_t key_len,
                      const uint8_t iv[CHACHA_IV_SIZE],
                      uint32_t counter);

bool ll_CHACHA12_Cipher(ll_CHACHA12_CTX *ctx,
                        const uint8_t *in, size_t in_len,
                        uint8_t *out);

// ChaCha20 (20 rounds)
#define CHACHA20_ROUNDS 20
typedef ll_CHACHA_CTX ll_CHACHA20_CTX;

bool ll_CHACHA20_init(ll_CHACHA20_CTX *ctx,
                      const uint8_t *key, size_t key_len,
                      const uint8_t iv[CHACHA_IV_SIZE],
                      uint32_t counter);

bool ll_CHACHA20_Cipher(ll_CHACHA20_CTX *ctx,
                        const uint8_t *in, size_t in_len,
                        uint8_t *out);

// XChaCha20 (20 rounds) extended iv 192 bits
#define XCHACHA20_ROUNDS 20
#define XCHACHA20_EXTENDED_IV_SIZE 24

typedef ll_CHACHA_CTX ll_XCHACHA20_CTX;

bool ll_XCHACHA20_init(ll_XCHACHA20_CTX *ctx,
                       const uint8_t *key, size_t key_len,
                       const uint8_t iv[XCHACHA20_EXTENDED_IV_SIZE],
                       uint32_t counter);

bool ll_XCHACHA20_Cipher(ll_XCHACHA20_CTX *ctx,
                         const uint8_t *in, size_t in_len,
                         uint8_t *out);

// ======================================
// ChaCha AEAD Variants / Modes
// ======================================
#define CHACHA20_POLY1305_TAG_SIZE 16
#define CHACHA20_POLY1305_IV_SIZE 12
#define CHACHA20_POLY1305MAX_AAD_LEN 0xFFFFFFFFFFFFULL  // ~16 PB, safely fits in 64-bit counters
#define CHACHA20_POLY1305_MAX_DATA_LEN ((uint64_t)256 * 1024 * 1024 * 1024) // 274_877_906_944 bytes

typedef struct {
    ll_CHACHA_CTX chacha_ctx;       // ChaCha internal context
    ll_POLY1305_CTX poly1305_ctx;   // poly1305 internal context
    uint64_t aad_len;               // total AAD length
    uint64_t data_len;              // total ciphertext/plaintext length
    int isEncrypt;                  // 1 = encrypting, 0 = decrypting
} ll_CHACHA20_POLY1305_CTX;

// Initialize streaming AEAD context
bool ll_CHACHA20_POLY13051305_Init(
    ll_CHACHA20_POLY1305_CTX *ctx,
    const uint8_t *key, size_t key_len,
    const uint8_t iv[CHACHA20_POLY1305_IV_SIZE],
    const uint8_t *aad, size_t aad_len, bool encrypt);

// Update: encrypt or decrypt a chunk of data
bool ll_CHACHA20_POLY1305_Update(
    ll_CHACHA20_POLY1305_CTX *ctx,
    const uint8_t *in, size_t in_len,
    uint8_t *out);

// Finalize: produce tag
bool ll_CHACHA20_POLY1305_Final(
    ll_CHACHA20_POLY1305_CTX *ctx,
    uint8_t tag[LL_POLY1305_TAG_LEN]);

#define CHACHA20_POLY1305_EXTENDED_IV_SIZE 24

typedef ll_CHACHA20_POLY1305_CTX ll_XCHACHA20_POLY1305_CTX;

// Initialize streaming AEAD context
bool ll_XCHACHA20_POLY1305_Init(
    ll_XCHACHA20_POLY1305_CTX *ctx,
    const uint8_t *key, size_t key_len,
    const uint8_t iv[CHACHA20_POLY1305_EXTENDED_IV_SIZE],
    const uint8_t *aad, size_t aad_len);

// Update: encrypt or decrypt a chunk of data
bool ll_XCHACHA20_POLY1305_Update(
    ll_XCHACHA20_POLY1305_CTX *ctx,
    const uint8_t *in, size_t in_len,
    uint8_t *out);

// Finalize: produce tag
bool ll_XCHACHA20_POLY1305_Final(
    ll_XCHACHA20_POLY1305_CTX *ctx,
    uint8_t tag[LL_POLY1305_TAG_LEN]);


#ifdef __cplusplus
}
#endif

#endif // CHACHA_H