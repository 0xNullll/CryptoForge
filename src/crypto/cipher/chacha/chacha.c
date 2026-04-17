/*
 * CryptoForge - chacha.c / ChaCha (ChaCha8, ChaCha12 And ChaCha20) Implementation
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

#include "../../../internal/crypto/chacha.h"

bool ll_CHACHA8_Init(ll_CHACHA8_CTX *ctx,
                     const uint8_t *key, size_t key_len,
                     const uint8_t iv[CHACHA_IV_SIZE],
                     uint32_t counter) {
    return ll_CHACHA_Init((ll_CHACHA_CTX *)ctx, key, key_len, iv, counter, CHACHA8_ROUNDS);                 
}

bool ll_CHACHA8_Cipher(ll_CHACHA8_CTX *ctx,
                       const uint8_t *in, size_t in_len,
                       uint8_t *out) {
    return ll_CHACHA_Cipher((ll_CHACHA_CTX *)ctx, in, in_len, out);
}

bool ll_CHACHA12_Init(ll_CHACHA12_CTX *ctx,
                     const uint8_t *key, size_t key_len,
                     const uint8_t iv[CHACHA_IV_SIZE],
                     uint32_t counter) {
    return ll_CHACHA_Init((ll_CHACHA_CTX *)ctx, key, key_len, iv, counter, CHACHA12_ROUNDS);                 
}

bool ll_CHACHA12_Cipher(ll_CHACHA12_CTX *ctx,
                       const uint8_t *in, size_t in_len,
                       uint8_t *out) {
    return ll_CHACHA_Cipher((ll_CHACHA_CTX *)ctx, in, in_len, out);
}

bool ll_CHACHA20_Init(ll_CHACHA20_CTX *ctx,
                     const uint8_t *key, size_t key_len,
                     const uint8_t iv[CHACHA_IV_SIZE],
                     uint32_t counter) {
    return ll_CHACHA_Init((ll_CHACHA_CTX *)ctx, key, key_len, iv, counter, CHACHA20_ROUNDS);                 
}

bool ll_CHACHA20_Cipher(ll_CHACHA20_CTX *ctx,
                       const uint8_t *in, size_t in_len,
                       uint8_t *out) {
    return ll_CHACHA_Cipher((ll_CHACHA_CTX *)ctx, in, in_len, out);
}