/*
 * CryptoForge - cf_defs.h
 *
 * Core forward declarations and shared type definitions for the
 * CryptoForge public API.
 *
 * This header centralizes opaque structure declarations used across
 * the library (hash, MAC, KDF, cipher, AEAD, encoder, etc.) in order
 * to:
 *
 *   - Avoid circular header dependencies
 *   - Reduce compilation coupling
 *   - Enforce opaque context design
 *   - Provide a single source of common algorithm entry definitions
 *
 * No algorithm implementations are defined here.
 * This file only declares shared types and generic algorithm
 * registration structures used internally by the framework.
 *
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CF_DEFS_H
#define CF_DEFS_H

#include <stdint.h>

/*
 * CryptoForge versioning
 *
 * CRYPTOFORGE_VERSION_MAJOR - breaking changes
 * CRYPTOFORGE_VERSION_MINOR - feature updates
 * CRYPTOFORGE_VERSION_PATCH - bug fixes / small changes
 *
 * CRYPTOFORGE_VERSION - packed integer version (MMmmpp)
 * CRYPTOFORGE_VERSION_STR - human-readable string
 */

#define CRYPTOFORGE_VERSION_MAJOR  0
#define CRYPTOFORGE_VERSION_MINOR  1
#define CRYPTOFORGE_VERSION_PATCH  4

#define CRYPTOFORGE_VERSION \
    ((CRYPTOFORGE_VERSION_MAJOR * 10000) + \
     (CRYPTOFORGE_VERSION_MINOR * 100) + \
     (CRYPTOFORGE_VERSION_PATCH))

#define CRYPTOFORGE_VERSION_STR "0.1.4"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _CF_ALGO_ENTRY {
    uint32_t flag;                  // algorithm ID / flag
    const void* (*getter_fn)(void); // returns pointer to algorithm descriptor (CF_HASH, CF_MAC, etc.)
} CF_ALGO_ENTRY;

typedef struct _CF_HASH CF_HASH;
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

typedef struct _CF_AEAD CF_AEAD;
typedef struct _CF_AEAD_CTX CF_AEAD_CTX;

typedef struct _CF_ENCODER CF_ENCODER;
typedef struct _CF_ENCODER_CTX CF_ENCODER_CTX;

#ifdef __cplusplus
}
#endif

#endif // CF_DEFS_H