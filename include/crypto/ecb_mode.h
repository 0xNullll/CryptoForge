/*
 * CryptoForge - ecb_mode.h / AES-ECB Interface
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

#ifndef ECB_MODE_H
#define ECB_MODE_H

#include "../utils/mem.h"
#include "../utils/misc.h"
#include "../config/libs.h"
#include "aes_core.h"

#ifdef __cplusplus
extern "C" {
#endif

//
// No IV, padding needed if plaintext not multiple of block. Independent blocks, patterns leak.
//

bool ll_AES_ECB_Encrypt(
    const ll_AES_KEY *key,
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);

bool ll_AES_ECB_Decrypt(
    const ll_AES_KEY *key,
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
);

#ifdef __cplusplus
}
#endif

#endif // ECB_MODE_H