/*
 * CryptoForge - xchacha20_poly1305.h / XChaCha20-Poly1305 Interface
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

#ifndef CHACHA20_POLY1305_H
#define CHACHA20_POLY1305_H

#include "../config/libs.h"

#include "../utils/mem.h"
#include "../utils/misc.h"
#include "../utils/bitops.h"
#include <CryptoForge/cf_status.h>

#include "chacha_core.h"
#include "chacha.h"
#include "poly1305.h"

#ifdef __cplusplus
extern "C" {
#endif

// ======================================
// ChaCha AEAD Variants / Modes
// ======================================
#define CHACHA20_POLY1305_TAG_SIZE 16
#define CHACHA20_POLY1305_IV_SIZE 12
#define CHACHA20_POLY1305_MAX_AAD_LEN 0xFFFFFFFFFFFFULL  // ~16 PB, safely fits in 64-bit counters
#define CHACHA20_POLY1305_MAX_DATA_LEN 274877906944ULL   // 256 GiB

typedef struct {
    ll_CHACHA_CTX chacha_ctx;       // ChaCha internal context
    ll_POLY1305_CTX poly1305_ctx;   // poly1305 internal context
    uint64_t aad_len;               // total AAD length
    uint64_t total_data_len;        // total ciphertext/plaintext length
    int isEncrypt;                  // 1 = encrypting, 0 = decrypting
} ll_CHACHA20_POLY1305_CTX;

// Initialize streaming AEAD context
bool ll_CHACHA20_POLY1305_Init(
    ll_CHACHA20_POLY1305_CTX *ctx,
    const uint8_t key[CHACHA_KEY_SIZE_256],
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

#ifdef __cplusplus
}
#endif

#endif // CHACHA20_POLY1305_H