/*
 * CryptoForge - aes_common.h / Common AES Utilities
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

#ifndef AES_COMMON_H
#define AES_COMMON_H

#include "../../../utils/mem.h"
#include "../../../config/libs.h"

#ifdef __cplusplus
extern "C" {
#endif


// =======================
// Big-endian conversions
// =======================
#if CPU_BIG_ENDIAN

// Big-endian CPU: memory already matches the hash format
static FORCE_INLINE uint32_t AES_BE32(const uint8_t *p) { 
    return *(const uint32_t*)p; 
}

static FORCE_INLINE uint64_t AES_BE64(const uint8_t *p) { 
    return *(const uint64_t*)p; 
}

static FORCE_INLINE void AES_PUT_BE32(uint8_t *p, uint32_t x) { 
    *(uint32_t*)p = x; 
}

static FORCE_INLINE void AES_PUT_BE64(uint8_t *p, uint64_t x) { 
    *(uint64_t*)p = x; 
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