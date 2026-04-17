/*
 * CryptoForge - chacha.h / ChaCha Variants Interface
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

#ifndef CHACHA_H
#define CHACHA_H

#include "../config/libs.h"

#include "../utils/mem.h"
#include "../utils/misc.h"
#include "../utils/bitops.h"
// #include "../utils/cf_status.h"
#include <CryptoForge/cf_status.h>

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

bool ll_CHACHA8_Init(ll_CHACHA8_CTX *ctx,
                     const uint8_t *key, size_t key_len,
                     const uint8_t iv[CHACHA_IV_SIZE],
                     uint32_t counter);

bool ll_CHACHA8_Cipher(ll_CHACHA8_CTX *ctx,
                       const uint8_t *in, size_t in_len,
                       uint8_t *out);

// ChaCha12 (12 rounds)
#define CHACHA12_ROUNDS 12
typedef ll_CHACHA_CTX ll_CHACHA12_CTX;

bool ll_CHACHA12_Init(ll_CHACHA12_CTX *ctx,
                      const uint8_t *key, size_t key_len,
                      const uint8_t iv[CHACHA_IV_SIZE],
                      uint32_t counter);

bool ll_CHACHA12_Cipher(ll_CHACHA12_CTX *ctx,
                        const uint8_t *in, size_t in_len,
                        uint8_t *out);

// ChaCha20 (20 rounds)
#define CHACHA20_ROUNDS 20
typedef ll_CHACHA_CTX ll_CHACHA20_CTX;

bool ll_CHACHA20_Init(ll_CHACHA20_CTX *ctx,
                      const uint8_t *key, size_t key_len,
                      const uint8_t iv[CHACHA_IV_SIZE],
                      uint32_t counter);

bool ll_CHACHA20_Cipher(ll_CHACHA20_CTX *ctx,
                        const uint8_t *in, size_t in_len,
                        uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif // CHACHA_H