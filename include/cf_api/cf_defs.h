/*
 * CryptoForge - cf_defs.h / CryptoForge API (hash, MAC, etc.) type definitions
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against WyChaProof test vectors. No hardware optimizations. Use with caution.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#ifndef CF_DEFS_H
#define CF_DEFS_H

#include "../config/libs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _CF_ALGO_ENTRY {
    uint32_t flag;                  // algorithm ID / flag
    const void* (*getter_fn)(void); // returns pointer to algorithm descriptor (CF_MD, CF_MAC, etc.)
} CF_ALGO_ENTRY;

typedef struct _CF_MD CF_MD;
typedef struct _CF_HASH_OPTS CF_HASH_OPTS;
typedef struct _CF_HASH_CTX CF_HASH_CTX;

typedef struct _CF_MAC CF_MAC;
typedef struct _CF_MAC_OPTS CF_MAC_OPTS;
typedef struct _CF_MAC_CTX CF_MAC_CTX;

typedef struct _CF_KDF CF_KDF;
typedef struct _CF_KDF_OPTS CF_KDF_OPTS;
typedef struct _CF_KDF_CTX CF_KDF_CTX;

typedef struct _CF_CIPHER CF_CIPHER;
typedef struct _CF_CIPHER_OPTS CF_CIPHER_OPTS;
typedef struct _CF_CIPHER_CTX CF_CIPHER_CTX;

typedef struct _CF_ENCODER CF_ENCODER;
typedef struct _CF_ENCODER_CTX CF_ENCODER_CTX;

#ifdef __cplusplus
}
#endif

#endif // CF_DEFS_H