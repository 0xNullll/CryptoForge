/*
 * CryptoForge - md5.h / MD5 Interface
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against WyChaProof test vectors. No hardware optimizations. Use with caution.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
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