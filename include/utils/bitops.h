/*
 * CryptoForge - bitopts.h / bit operation Utilities
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

#ifndef BITOPS_h
#define BITOPS_h

#include "mem.h"
#include "misc.h" 
#include "../config/libs.h"

#ifdef __cplusplus
extern "C" {
#endif

// =======================
// Bit rotation helpers
// =======================
static FORCE_INLINE uint32_t rotl32(uint32_t x, uint32_t n) {
    n &= 31;
    return (x << n) | (x >> (32 - n));
}

static FORCE_INLINE uint32_t rotr32(uint32_t x, uint32_t n) {
    n &= 31;
    return (x >> n) | (x << (32 - n));
}

static FORCE_INLINE uint64_t rotl64(uint64_t x, uint64_t n) {
    n &= 63;
    return (x << n) | (x >> (64 - n));
}

static FORCE_INLINE uint64_t rotr64(uint64_t x, uint64_t n) {
    n &= 63;
    return (x >> n) | (x << (64 - n));
}

#define ROTL32(x,n) rotl32(x,n)
#define ROTR32(x,n) rotr32(x,n)
#define ROTL64(x,n) rotl64(x,n)
#define ROTR64(x,n) rotr64(x,n)

// =======================
// Big-endian conversions
// =======================
#if CPU_BIG_ENDIAN
// Big-endian CPU: memory already matches the hash format
static FORCE_INLINE uint32_t BE32(const uint8_t *p) { 
    uint32_t x;
    SECURE_MEMCPY(&x, p, sizeof(x));
    return x; 
}

static FORCE_INLINE uint64_t BE64(const uint8_t *p) { 
    uint64_t x;
    SECURE_MEMCPY(&x, p, sizeof(x));
    return x; 
}

static FORCE_INLINE void PUT_BE32(uint8_t *p, uint32_t x) { 
    SECURE_MEMCPY(p, &x, sizeof(x));
}

static FORCE_INLINE void PUT_BE64(uint8_t *p, uint64_t x) { 
    SECURE_MEMCPY(p, &x, sizeof(x));
}
#else
// Little-endian CPU: convert manually
static FORCE_INLINE uint32_t BE32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |
           ((uint32_t)p[3]);
}

static FORCE_INLINE uint64_t BE64(const uint8_t *p) {
    return ((uint64_t)p[0] << 56) |
           ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) |
           ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) |
           ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8)  |
           ((uint64_t)p[7]);
}

static FORCE_INLINE void PUT_BE32(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)(x >> 24);
    p[1] = (uint8_t)(x >> 16);
    p[2] = (uint8_t)(x >> 8);
    p[3] = (uint8_t)x;
}

static FORCE_INLINE void PUT_BE64(uint8_t *p, uint64_t x) {
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

#define LOAD32(p)    BE32((const uint8_t*)(p))
#define STORE32(p,x) PUT_BE32((uint8_t*)(p), x)
#define LOAD64(p)    BE64((const uint8_t*)(p))
#define STORE64(p,x) PUT_BE64((uint8_t*)(p), x)

// =======================
// Twisted load/store helpers
// For Keccak / SHA-3 style algorithms
// Only difference: twisted byte order
// =======================
#if CPU_BIG_ENDIAN
// big-endian CPU: memory matches algorithm -> no-op
static FORCE_INLINE uint32_t TWISTED32(const uint8_t *p) {
    uint32_t x;
    SECURE_MEMCPY(p, x, sizeof(x));
    return x;
}

static FORCE_INLINE void TWISTED_PUT32(uint8_t *p, uint32_t x) {
    SECURE_MEMCPY(p, x, sizeof(x));
}

static FORCE_INLINE uint64_t TWISTED64(const uint8_t *p) {
    uint64_t x;
    SECURE_MEMCPY(p, x, sizeof(x));
    return x;
}

static FORCE_INLINE void TWISTED_PUT64(uint8_t *p, uint64_t x) {
    SECURE_MEMCPY(p, x, sizeof(x));
}
#else
static FORCE_INLINE uint32_t TWISTED32(const uint8_t *p) {
    return (uint32_t)p[0]         |
           ((uint32_t)p[1] << 8)  |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static FORCE_INLINE void TWISTED_PUT32(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)x;
    p[1] = (uint8_t)(x >> 8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
}

static FORCE_INLINE uint64_t TWISTED64(const uint8_t *p) {
    return  (uint64_t)p[0]        |
           ((uint64_t)p[1] << 8)  |
           ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
}
static FORCE_INLINE void TWISTED_PUT64(uint8_t *p, uint64_t x) {
    p[0] = (uint8_t)x;
    p[1] = (uint8_t)(x >> 8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
    p[4] = (uint8_t)(x >> 32);
    p[5] = (uint8_t)(x >> 40);
    p[6] = (uint8_t)(x >> 48);
    p[7] = (uint8_t)(x >> 56);
}
#endif

#define TWISTED_LOAD32(p)    TWISTED32((const uint8_t*)(p))
#define TWISTED_STORE32(p,x) TWISTED_PUT32((uint8_t*)(p), x)
#define TWISTED_LOAD64(p)    TWISTED64((const uint8_t*)(p))
#define TWISTED_STORE64(p,x) TWISTED_PUT64((uint8_t*)(p), x)

#ifdef __cplusplus
}
#endif

#endif // BITOPS_h