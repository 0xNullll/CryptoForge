/*
 * CryptoForge - cf_defs.h / CryptoForge API (hash/encoder) type definitions
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

typedef struct _CF_MD_ENTRY CF_MD_ENTRY;

typedef struct _CF_MAC CF_MAC;

typedef struct _CF_XOF_OPTS CF_XOF_OPTS;

typedef struct _CF_HASH_CTX CF_HASH_CTX;

typedef struct _CF_ENCODER CF_ENCODER;

typedef struct _CF_ENCODER_CTX CF_ENCODER_CTX;

#ifdef __cplusplus
}
#endif

#endif // CF_DEFS_H