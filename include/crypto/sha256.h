/*
 * CryptoForge - sha256.h / SHA-256 (SHA-256, and SHA-224) Interface
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against WyChaProof test vectors. No hardware optimizations. Use with caution.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#ifndef SHA2_H
#define SHA2_H

#include "../utils/bitops.h"
#include "../config/crypto_config.h"
#include "../utils/misc.h"
#include "../utils/mem.h"

#ifdef __cplusplus
extern "C" {
#endif

// ======================================
// SHA-256
// ======================================
#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];
    uint64_t len;
    uint8_t buf[SHA256_BLOCK_SIZE];
    size_t buf_len;
} ll_SHA256_CTX;

bool ll_sha256_init(ll_SHA256_CTX *ctx);
bool ll_sha256_update(ll_SHA256_CTX *ctx, const uint8_t *data, size_t len);
bool ll_sha256_final(ll_SHA256_CTX *ctx, uint8_t digest[SHA256_DIGEST_SIZE]);

// ======================================
// SHA-224 (truncated SHA-256)
// ======================================
#define SHA224_BLOCK_SIZE 64
#define SHA224_DIGEST_SIZE 28

typedef ll_SHA256_CTX ll_SHA224_CTX;

bool ll_sha224_init(ll_SHA224_CTX *ctx);
bool ll_sha224_update(ll_SHA224_CTX *ctx, const uint8_t *data, size_t len);
bool ll_sha224_final(ll_SHA224_CTX *ctx, uint8_t digest[SHA224_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif // SHA2_H
