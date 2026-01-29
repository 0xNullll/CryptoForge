/*
 * CryptoForge - md5.h / MD5 Hash Interface
 * Copyright (C) 2025 0xNullll
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the MIT License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * You should have received a copy of the MIT License along with this program.
 * If not, see <https://opensource.org/licenses/MIT>.
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