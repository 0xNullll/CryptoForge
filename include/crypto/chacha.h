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
#include "../config/libs.h"
#include "chacha_core.h"

#ifdef __cplusplus
extern "C" {
#endif

// ======================================
// ChaCha Variants / Modes
// ======================================

// ChaCha8 (8 rounds)
#define CHACHA8_ROUNDS 8
typedef ll_CHACHA_CTX ll_CHACHA8_CTX;

// Key length is now flexible; the underlying init function handles it
bool ll_CHACHA8_init(ll_CHACHA8_CTX *ctx,
                     const uint8_t *key, size_t key_len,
                     const uint8_t nonce[CHACHA_NONCE_SIZE],
                     uint32_t counter);

bool ll_CHACHA8_Cipher(ll_CHACHA8_CTX *ctx,
                       const uint8_t *in, size_t in_len,
                       uint8_t *out);

// ChaCha12 (12 rounds)
#define CHACHA12_ROUNDS 12
typedef ll_CHACHA_CTX ll_CHACHA12_CTX;

bool ll_CHACHA12_init(ll_CHACHA12_CTX *ctx,
                      const uint8_t *key, size_t key_len,
                      const uint8_t nonce[CHACHA_NONCE_SIZE],
                      uint32_t counter);

bool ll_CHACHA12_Cipher(ll_CHACHA12_CTX *ctx,
                        const uint8_t *in, size_t in_len,
                        uint8_t *out);

// ChaCha20 (20 rounds)
#define CHACHA20_ROUNDS 20
typedef ll_CHACHA_CTX ll_CHACHA20_CTX;

bool ll_CHACHA20_init(ll_CHACHA20_CTX *ctx,
                      const uint8_t *key, size_t key_len,
                      const uint8_t nonce[CHACHA_NONCE_SIZE],
                      uint32_t counter);

bool ll_CHACHA20_Cipher(ll_CHACHA20_CTX *ctx,
                        const uint8_t *in, size_t in_len,
                        uint8_t *out);

// XChaCha20 (20 rounds) extended nonce 192 bits
#define XCHACHA20_ROUNDS 20
#define XCHACHA20_EXTENDED_NONCE_SIZE 24

typedef ll_CHACHA_CTX ll_XCHACHA20_CTX;

bool ll_XCHACHA20_init(ll_XCHACHA20_CTX *ctx,
                       const uint8_t *key, size_t key_len,
                       const uint8_t nonce[XCHACHA20_EXTENDED_NONCE_SIZE],
                       uint32_t counter);

bool ll_XCHACHA20_Cipher(ll_XCHACHA20_CTX *ctx,
                         const uint8_t *in, size_t in_len,
                         uint8_t *out);

// ======================================
// ChaCha AEAD Variants / Modes
// ======================================
#define CHACHA20_POLY1305_TAG_SIZE 16
#define CHACHA20_POLY1305_NONCE_SIZE 12

typedef struct {
    ll_CHACHA20_CTX chacha;                // ChaCha20 internal context
    uint8_t poly_key[CHACHA_KEY_SIZE_256]; // Poly1305 one-time key
    size_t aad_len;                        // total AAD length
    size_t data_len;                       // total ciphertext/plaintext length
} ll_CHACHA20_POLY_CTX;

// Initialize streaming AEAD context
bool ll_CHACHA20_POLY_Init(ll_CHACHA20_POLY_CTX *ctx,
                           const uint8_t *key, size_t key_len,
                           const uint8_t nonce[CHACHA20_POLY1305_NONCE_SIZE],
                           const uint8_t *aad, size_t aad_len);

// Update: encrypt or decrypt a chunk of data
bool ll_CHACHA20_POLY_Update(ll_CHACHA20_POLY_CTX *ctx,
                             const uint8_t *in, size_t in_len,
                             uint8_t *out, bool encrypt);

// Finalize: produce tag (encryption) or verify tag (decryption)
bool ll_CHACHA20_POLY_Final(ll_CHACHA20_POLY_CTX *ctx,
                            uint8_t *tag, size_t tag_len);

#define CHACHA20_POLY1305_TAG_SIZE 16
#define XCHACHA20_POLY1305_EXTENDED_NONCE_SIZE 24

typedef ll_CHACHA20_POLY_CTX ll_XCHACHA20_POLY_CTX;

// Initialize streaming AEAD context
bool ll_XCHACHA20_POLY_Init(ll_XCHACHA20_POLY_CTX *ctx,
                           const uint8_t *key, size_t key_len,
                           const uint8_t nonce[XCHACHA20_POLY1305_EXTENDED_NONCE_SIZE],
                           const uint8_t *aad, size_t aad_len);

// Update: encrypt or decrypt a chunk of data
bool ll_XCHACHA20_POLY_Update(ll_XCHACHA20_POLY_CTX *ctx,
                             const uint8_t *in, size_t in_len,
                             uint8_t *out, bool encrypt);

// Finalize: produce tag (encryption) or verify tag (decryption)
bool ll_XCHACHA20_POLY_Final(ll_XCHACHA20_POLY_CTX *ctx,
                            uint8_t *tag, size_t tag_len);


#ifdef __cplusplus
}
#endif

#endif // CHACHA_H