/*
 * CryptoForge - sha1.h / SHA-1 Interface
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against WyChaProof test vectors. No hardware optimizations. Use with caution.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#ifndef SHA1_H
#define SHA1_H

#include "../utils/bitops.h"
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