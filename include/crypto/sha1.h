/*
 * CryptoForge - sha1.h / SHA-1 Hash Interface
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

#ifndef SHA1_H
#define SHA1_H

#include "hash_common.h"
#include "../config/crypto_config.h"
#include "../utils/mem.h"

#ifdef __cplusplus
extern "C" {
#endif

// ======================================
// SHA-1
// ======================================
#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_SIZE 20

typedef struct {
   uint32_t h0, h1, h2, h3, h4;
   uint64_t len;
   uint8_t buf[SHA1_BLOCK_SIZE];
   size_t num;
} ll_SHA1_CTX;

bool ll_sha1_init(ll_SHA1_CTX *ctx);
bool ll_sha1_update(ll_SHA1_CTX *ctx, const uint8_t *data, size_t len);
bool ll_sha1_final(ll_SHA1_CTX *ctx, uint8_t digest[SHA1_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif // SHA1_H