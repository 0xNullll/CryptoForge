/*
 * CryptoForge - ecb_mode.c / AES-ECB Implementation
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

#include "../../../internal/crypto/ecb_mode.h"

bool ll_AES_ECB_Encrypt(const ll_AES_KEY *key, const uint8_t *in, size_t in_len, uint8_t *out) {
    if (!key || !in || (in_len % AES_BLOCK_SIZE) != 0 || !out) return false; 

    for (size_t i = 0; i < in_len; i += AES_BLOCK_SIZE) {
        if (!ll_AES_EncryptBlock(key, in + i, out + i)) return false;
    }

    return true;
}

bool ll_AES_ECB_Decrypt(const ll_AES_KEY *key, const uint8_t *in, size_t in_len, uint8_t *out) {
    if (!key || !in || (in_len % AES_BLOCK_SIZE) != 0 || !out) return false; 

    for (size_t i = 0; i < in_len; i += AES_BLOCK_SIZE) {
        if (!ll_AES_DecryptBlock(key, in + i, out + i)) return false;
    }

    return true;
}