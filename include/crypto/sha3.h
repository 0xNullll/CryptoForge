/*
 * CryptoForge - sha3.h / SHA-3 (SHA-3-224, SHA-3-256, SHA3-384, and SHA3-512) Hash Interface
 * Copyright (C) 2026 0xNullll
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

#ifndef SHA3_H
#define SHA3_H

#include "../utils/bitops.h"
#include "../config/crypto_config.h"
#include "../utils/misc.h"
#include "keccak.h"

#ifdef __cplusplus
extern "C" {
#endif

// ======================================
// SHA3 (Low-level wrappers around Keccak)
// ======================================

// ======================================
// SHA3-224
// ======================================
#define SHA3_224_BLOCK_SIZE 144
#define SHA3_224_DIGEST_SIZE 28
#define SHA3_224_DOMAIN 0x06

typedef ll_KECCAK_CTX ll_SHA3_224_CTX;

bool ll_sha3_224_init(ll_SHA3_224_CTX *ctx);
bool ll_sha3_224_absorb(ll_SHA3_224_CTX *ctx, const uint8_t *data, size_t len);
bool ll_sha3_224_final(ll_SHA3_224_CTX *ctx);
bool ll_sha3_224_squeeze(ll_SHA3_224_CTX *ctx, uint8_t *output, size_t outlen);

// ======================================
// SHA3-256
// ======================================
#define SHA3_256_BLOCK_SIZE 136
#define SHA3_256_DIGEST_SIZE 32
#define SHA3_256_DOMAIN 0x06

typedef ll_KECCAK_CTX ll_SHA3_256_CTX;

bool ll_sha3_256_init(ll_SHA3_256_CTX *ctx);
bool ll_sha3_256_absorb(ll_SHA3_256_CTX *ctx, const uint8_t *data, size_t len);
bool ll_sha3_256_final(ll_SHA3_256_CTX *ctx);
bool ll_sha3_256_squeeze(ll_SHA3_256_CTX *ctx, uint8_t *output, size_t outlen);

// ======================================
// SHA3-384
// ======================================
#define SHA3_384_BLOCK_SIZE 104
#define SHA3_384_DIGEST_SIZE 48
#define SHA3_384_DOMAIN 0x06

typedef ll_KECCAK_CTX ll_SHA3_384_CTX;

bool ll_sha3_384_init(ll_SHA3_384_CTX *ctx);
bool ll_sha3_384_absorb(ll_SHA3_384_CTX *ctx, const uint8_t *data, size_t len);
bool ll_sha3_384_final(ll_SHA3_384_CTX *ctx);
bool ll_sha3_384_squeeze(ll_SHA3_384_CTX *ctx, uint8_t *output, size_t outlen);

// ======================================
// SHA3-512
// ======================================
#define SHA3_512_BLOCK_SIZE 72
#define SHA3_512_DIGEST_SIZE 64
#define SHA3_512_DOMAIN 0x06

typedef ll_KECCAK_CTX ll_SHA3_512_CTX;

bool ll_sha3_512_init(ll_SHA3_512_CTX *ctx);
bool ll_sha3_512_absorb(ll_SHA3_512_CTX *ctx, const uint8_t *data, size_t len);
bool ll_sha3_512_final(ll_SHA3_512_CTX *ctx);
bool ll_sha3_512_squeeze(ll_SHA3_512_CTX *ctx, uint8_t *output, size_t outlen);

#ifdef __cplusplus
}
#endif

#endif // SHA3_H