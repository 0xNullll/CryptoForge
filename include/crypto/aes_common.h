/*
 * CryptoForge - aes_common.h / Common AES Utilities
 * Copyright (C) 2025 0xNullll
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

#ifndef AES_COMMON_H
#define AES_COMMON_H

#include "../utils/mem.h"
#include "../config/libs.h"

#ifdef __cplusplus
extern "C" {
#endif


// =======================
// Big-endian conversions
// =======================
#if CPU_BIG_ENDIAN
// Big-endian CPU: memory already matches the hash format
static FORCE_INLINE uint32_t AES_BE32(const uint8_t *p) { 
    uint32_t x;
    SECURE_MEMCPY(&x, p, sizeof(x));
    return x; 
}

static FORCE_INLINE uint64_t AES_BE64(const uint8_t *p) { 
    uint64_t x;
    SECURE_MEMCPY(&x, p, sizeof(x));
    return x; 
}

static FORCE_INLINE void AES_PUT_BE32(uint8_t *p, uint32_t x) { 
    SECURE_MEMCPY(p, &x, sizeof(x));
}

static FORCE_INLINE void AES_PUT_BE64(uint8_t *p, uint64_t x) { 
    SECURE_MEMCPY(p, &x, sizeof(x));
}
#else
// Little-endian CPU: convert manually
static FORCE_INLINE uint32_t AES_BE32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |
           ((uint32_t)p[3]);
}

static FORCE_INLINE uint64_t AES_BE64(const uint8_t *p) {
    return ((uint64_t)p[0] << 56) |
           ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) |
           ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) |
           ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8)  |
           ((uint64_t)p[7]);
}

static FORCE_INLINE void AES_PUT_BE32(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)(x >> 24);
    p[1] = (uint8_t)(x >> 16);
    p[2] = (uint8_t)(x >> 8);
    p[3] = (uint8_t)x;
}

static FORCE_INLINE void AES_PUT_BE64(uint8_t *p, uint64_t x) {
    p[0] = (uint8_t)(x >> 56);
    p[1] = (uint8_t)(x >> 48);
    p[2] = (uint8_t)(x >> 40);
    p[3] = (uint8_t)(x >> 32);
    p[4] = (uint8_t)(x >> 24);
    p[5] = (uint8_t)(x >> 16);
    p[6] = (uint8_t)(x >> 8);
    p[7] = (uint8_t)x;
}
#endif

#define AES_LOAD32(p)    AES_BE32((const uint8_t*)(p))
#define AES_STORE32(p,x) AES_PUT_BE32((uint8_t*)(p), x)
#define AES_LOAD64(p)    AES_BE64((const uint8_t*)(p))
#define AES_STORE64(p,x) AES_PUT_BE64((uint8_t*)(p), x)

#ifdef __cplusplus
}
#endif

#endif // AES_COMMON_H