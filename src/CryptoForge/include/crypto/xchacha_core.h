/*
 * CryptoForge - xchacha.h / XChaCha Core Interface
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

#ifndef XCHACHA_CORE_H
#define XCHACHA_CORE_H

#include "../config/libs.h"

#include "../utils/mem.h"
#include "../utils/misc.h"
#include "../utils/bitops.h"

#include "chacha_core.h"

#ifdef __cplusplus
extern "C" {
#endif

#define XCHACHA_KEY_SIZE 32           // 256-bit key
#define XCHACHA_EXTENDED_IV_SIZE 24   // 192-bit nonce

// Derive 256-bit subkey from 256-bit key + 16-byte nonce
bool ll_HChaCha_DeriveSubkey(
    const uint8_t key[XCHACHA_KEY_SIZE],
    const uint8_t iv[16],
    uint8_t out[32],
    int rounds);

#ifdef __cplusplus
}
#endif

#endif // XCHACHA_CORE_H