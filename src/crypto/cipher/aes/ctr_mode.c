/*
 * CryptoForge - ctr_mode.c / AES-CTR Implementation
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

#include "../../../internal/crypto/ctr_mode.h"

bool ll_AES_CTR_Process(
    const ll_AES_KEY *key,
    uint8_t counter[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len_bytes,
    uint8_t *out);

bool ll_AES_CTR_Process(
    const ll_AES_KEY *key,
    uint8_t counter[AES_BLOCK_SIZE],
    const uint8_t *in,
    size_t in_len_bytes,
    uint8_t *out) {
    if (!key || !counter || !in || !out)
        return false;

    bool ok = false;

    uint8_t keystream[AES_BLOCK_SIZE];
    size_t keystream_used = AES_BLOCK_SIZE; // force first block generation

    for (size_t i = 0; i < in_len_bytes; ) {
        // generate new keystream block if needed
        if (keystream_used == AES_BLOCK_SIZE) {
            if (!ll_AES_EncryptBlock(key, counter, keystream))
                goto cleanup;

            // increment 16-byte counter (big-endian)
            uint64_t hi = LOAD64BE(counter);
            uint64_t lo = LOAD64BE(counter + 8);
            if (++lo == 0) hi++;
            STORE64BE(counter, hi);
            STORE64BE(counter + 8, lo);

            keystream_used = 0;
        }

        size_t remaining = in_len_bytes - i;
        size_t chunk = AES_BLOCK_SIZE - keystream_used;
        if (chunk > remaining) chunk = remaining;

        // XOR one byte at a time
        for (size_t j = 0; j < chunk; j++)
            out[i + j] = in[i + j] ^ keystream[keystream_used + j];

        i += chunk;
        keystream_used += chunk;
    }

    ok = true;

cleanup:
    SECURE_ZERO(keystream, sizeof(keystream));
    keystream_used = 0;

    return ok;
}

bool ll_AES_CTR_Encrypt(const ll_AES_KEY *key, uint8_t counter[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len, uint8_t *out) {
    return ll_AES_CTR_Process(key, counter, in, in_len, out);
}

bool ll_AES_CTR_Decrypt(const ll_AES_KEY *key, uint8_t counter[AES_BLOCK_SIZE], const uint8_t *in, size_t in_len, uint8_t *out) {
    return ll_AES_CTR_Process(key, counter, in, in_len, out);   
}