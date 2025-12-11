/*
 * CryptoForge - sha512.h / SHA-512 (SHA-384, SHA-512, SHA-512-224, and SHA-512-256) Hash Interface
 * Copyright (C) 2025 0xNullll
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#ifndef SHA512_H
#define SHA512_H

#include "../hash_common.h"
#include "../../../config/crypto_config.h"
#include "../../../utils/misc_utils.h"
#include "../../../utils/mem.h"

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
