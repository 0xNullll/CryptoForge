/*
 * CryptoForge - xchacha.h / XChaCha (XChaCha8, XChaCha12, And XChaCha20) Interface
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
#ifndef XCHACHA_H
#define XCHACHA_H

#include "../config/libs.h"

#include "../utils/mem.h"
#include "../utils/misc.h"
#include "../utils/bitops.h"
#include "../utils/cf_status.h"

#include "chacha_core.h"
#include "chacha.h"
#include "xchacha_core.h"
#include "poly1305.h"

#ifdef __cplusplus
extern "C" {
#endif

// ======================================
// XChaCha Variants / Modes
// ======================================

// ----------------------------
// XChaCha8 (8 rounds)
#define XCHACHA8_ROUNDS 8
typedef ll_CHACHA_CTX ll_XCHACHA8_CTX;

bool ll_XCHACHA8_Init(ll_XCHACHA8_CTX *ctx,
                       const uint8_t key[XCHACHA_KEY_SIZE],
                       const uint8_t iv[XCHACHA_EXTENDED_IV_SIZE]);

bool ll_XCHACHA8_Cipher(ll_XCHACHA8_CTX *ctx,
                        const uint8_t *in, size_t in_len,
                        uint8_t *out);

// ----------------------------
// XChaCha12 (12 rounds)
#define XCHACHA12_ROUNDS 12
typedef ll_CHACHA_CTX ll_XCHACHA12_CTX;

bool ll_XCHACHA12_Init(ll_XCHACHA12_CTX *ctx,
                       const uint8_t key[XCHACHA_KEY_SIZE],
                       const uint8_t iv[XCHACHA_EXTENDED_IV_SIZE]);

bool ll_XCHACHA12_Cipher(ll_XCHACHA12_CTX *ctx,
                         const uint8_t *in, size_t in_len,
                         uint8_t *out);

// ----------------------------
// XChaCha20 (20 rounds)
#define XCHACHA20_ROUNDS 20
typedef ll_CHACHA_CTX ll_XCHACHA20_CTX;

bool ll_XCHACHA20_Init(ll_XCHACHA20_CTX *ctx,
                       const uint8_t key[XCHACHA_KEY_SIZE],
                       const uint8_t iv[XCHACHA_EXTENDED_IV_SIZE]);

bool ll_XCHACHA20_Cipher(ll_XCHACHA20_CTX *ctx,
                         const uint8_t *in, size_t in_len,
                         uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif // XCHACHA_H