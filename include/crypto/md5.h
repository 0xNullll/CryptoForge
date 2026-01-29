/*
 * CryptoForge - md5.h / MD5 Hash Interface
 * Copyright (C) 2025 0xNullll
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License in the file LICENSE in the
 * source distribution or at:
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * This software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
 * OR CONDITIONS OF ANY KIND, either express or implied. See the License
 * for the specific language governing permissions and limitations under
 * the License.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#ifndef MD5_H
#define MD5_H

#include "hash_common.h"
#include "../config/crypto_config.h"
#include "../utils/mem.h"

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