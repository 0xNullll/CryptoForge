/*
 * CryptoForge - cf_defs.h / CryptoForge API (hash/encoder) type definitions
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