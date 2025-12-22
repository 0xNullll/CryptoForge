/*
 * CryptoForge - evp_defs.h / EVP (hash/encoder) type definitions
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

#ifndef EVP_DEFS_H
#define EVP_DEFS_H

#include "../../config/libs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _EVP_MD EVP_MD;

typedef struct _EVP_MD_ENTRY EVP_MD_ENTRY;

typedef struct _EVP_XOF_OPTS EVP_XOF_OPTS;

typedef struct _EVP_HASH_CTX EVP_HASH_CTX;

typedef struct _EVP_ENCODER EVP_ENCODER;

typedef struct _EVP_ENCODER_CTX EVP_ENCODER_CTX;

#ifdef __cplusplus
}
#endif

#endif // EVP_DEFS_H