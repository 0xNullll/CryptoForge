/*
 * CryptoForge - ofb_mode.c / AES-OFB Implementation
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

#include "../../../include/crypto/ofb_mode.h"

static bool ll_AES_OFB_Process(const ll_AES_KEY *key, const uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len_bytes, uint8_t *out) {
    if (!key || !iv || !in || !out) return false;

    bool ok = false;

    uint8_t state[AES_BLOCK_SIZE];
    uint8_t keystream[AES_BLOCK_SIZE];
    size_t keystream_used = AES_BLOCK_SIZE; // force first block generation

    SECURE_MEMCPY(state, iv, AES_BLOCK_SIZE);

    for (size_t i = 0; i < in_len_bytes; i++) {
        // Generate new keystream block if all bytes used
        if (keystream_used == AES_BLOCK_SIZE) {
            if (!ll_AES_EncryptBlock(key, state, keystream)) 
                goto cleanup;

            SECURE_MEMCPY(state, keystream, AES_BLOCK_SIZE); // update OFB feedback
            keystream_used = 0;
        }

        // XOR plaintext byte with current keystream byte
        out[i] = in[i] ^ keystream[keystream_used++];
    }

    ok = true;

cleanup:
    SECURE_ZERO(state, sizeof(state));
    SECURE_ZERO(keystream, sizeof(keystream));
    keystream_used = 0; // not secret, but avoids reuse bugs

    return ok;
}

bool ll_AES_OFB_Encrypt(const ll_AES_KEY *key, uint8_t const  iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len, uint8_t *out) {
    return ll_AES_OFB_Process(key, iv, in, in_len, out);
}

bool ll_AES_OFB_Decrypt(const ll_AES_KEY *key, const  uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len, uint8_t *out) {
    return ll_AES_OFB_Process(key, iv, in, in_len, out);
}
