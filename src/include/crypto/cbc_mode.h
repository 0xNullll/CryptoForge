/*
 * CryptoForge - cbc_mode.h / AES-CBC Interface
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

#ifndef CBC_MODE_H
#define CBC_MODE_H

#include "../utils/mem.h"
#include "../utils/misc.h"
#include "../config/libs.h"

#include "aes_core.h"

#ifdef __cplusplus
extern "C" {
#endif

//
// IV must be UNPREDICTABLE, padding needed. C[i] = E(P[i] XOR C[i-1]); first block leaks if IV predictable.
//

bool ll_AES_CBC_Encrypt(
    const ll_AES_KEY *key,
    const uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);

bool ll_AES_CBC_Decrypt(
    const ll_AES_KEY *key,
    const uint8_t iv[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);

#ifdef __cplusplus
}
#endif

#endif // CBC_MODE_H