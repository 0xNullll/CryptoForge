/*
 * CryptoForge - md5.h / MD5 Interface
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

#ifndef MD5_H
#define MD5_H

#include "../config/crypto_config.h"
#include "../utils/mem.h"
#include "../utils/misc.h"
#include "../utils/bitops.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MD5_BLOCK_SIZE 64
#define MD5_DIGEST_SIZE 16

typedef struct {
    uint32_t state[4];       // A, B, C, D
    uint64_t bitlen;         // total length in bits
    uint8_t buffer[MD5_BLOCK_SIZE];
    size_t buffer_len;
} ll_MD5_CTX;

// Low-level MD5 API
bool ll_md5_init(ll_MD5_CTX *ctx);
bool ll_md5_update(ll_MD5_CTX *ctx, const uint8_t *data, size_t len);
bool ll_md5_final(ll_MD5_CTX *ctx, uint8_t digest[MD5_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif // MD5_H