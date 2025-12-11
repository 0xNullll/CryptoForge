/*
 * CryptoForge - evp_defs.h / EVP (hash/encoder) type definitions
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