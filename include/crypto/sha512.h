/*
 * CryptoForge - sha512.h / SHA-512 (SHA-384, SHA-512, SHA-512-224, and SHA-512-256) Hash Interface
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

#ifndef SHA512_H
#define SHA512_H

#include "hash_common.h"
#include "../config/crypto_config.h"
#include "../utils/misc.h"
#include "../utils/mem.h"

#ifdef __cplusplus
extern "C" {
#endif

// ======================================
// SHA-512 Low-level
// ======================================
#define SHA512_BLOCK_SIZE 128
#define SHA512_DIGEST_SIZE 64

typedef struct {
    uint64_t state[8];
    uint64_t Nl, Nh;
    uint8_t buf[SHA512_BLOCK_SIZE];
    size_t buf_len;
} ll_SHA512_CTX;

bool ll_sha512_init(ll_SHA512_CTX *ctx);
bool ll_sha512_update(ll_SHA512_CTX *ctx, const uint8_t *data, size_t len);
bool ll_sha512_final(ll_SHA512_CTX *ctx, uint8_t digest[SHA512_DIGEST_SIZE]);

// ======================================
// SHA-384 Low-level (truncated SHA-512)
// ======================================
#define SHA384_BLOCK_SIZE 128
#define SHA384_DIGEST_SIZE 48

typedef ll_SHA512_CTX ll_SHA384_CTX;

bool ll_sha384_init(ll_SHA384_CTX *ctx);
bool ll_sha384_update(ll_SHA384_CTX *ctx, const uint8_t *data, size_t len);
bool ll_sha384_final(ll_SHA384_CTX *ctx, uint8_t digest[SHA384_DIGEST_SIZE]);

// ======================================
// SHA-512/224 Low-level (truncated SHA-512)
// ======================================
#define SHA512_224_BLOCK_SIZE 128
#define SHA512_224_DIGEST_SIZE 28

typedef ll_SHA512_CTX ll_SHA512_224_CTX;

bool ll_sha512_224_init(ll_SHA512_224_CTX *ctx);
bool ll_sha512_224_update(ll_SHA512_224_CTX *ctx, const uint8_t *data, size_t len);
bool ll_sha512_224_final(ll_SHA512_224_CTX *ctx, uint8_t digest[SHA512_224_DIGEST_SIZE]);

// ======================================
// SHA-512/256 Low-level (truncated SHA-512)
// ======================================
#define SHA512_256_BLOCK_SIZE 128
#define SHA512_256_DIGEST_SIZE 32

typedef ll_SHA512_CTX ll_SHA512_256_CTX;

bool ll_sha512_256_init(ll_SHA512_256_CTX *ctx);
bool ll_sha512_256_update(ll_SHA512_256_CTX *ctx, const uint8_t *data, size_t len);
bool ll_sha512_256_final(ll_SHA512_256_CTX *ctx, uint8_t digest[SHA512_256_DIGEST_SIZE]);

#endif // ENABLE_SHA

#ifdef __cplusplus
}
#endif
