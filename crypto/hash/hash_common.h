/*
 * CryptoForge - hash_common.h / Common Hash Utilities
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

#ifndef HASH_COMMON_H
#define HASH_COMMON_H

#include "../../config/libs.h"
#include "../../config/crypto_config.h"
#include "../../utils/mem.h"
#include "../../utils/misc_utils.h"

// =======================
// Bit rotation helpers
// =======================
static FORCE_INLINE uint32_t rotl32(uint32_t x, uint32_t n) {
    n &= 31;
    return (x << n) | (x >> (32 - n));
}

static FORCE_INLINE uint64_t rotl64(uint64_t x, uint64_t n) {
    n &= 63;
    return (x << n) | (x >> (64 - n));
}

static FORCE_INLINE uint32_t rotr32(uint32_t x, uint32_t n) {
    n &= 31;
    return (x >> n) | (x << (32 - n));
}

static FORCE_INLINE uint64_t rotr64(uint64_t x, uint64_t n) {
    n &= 63;
    return (x >> n) | (x << (64 - n));
}

#define ROTL32(x,n) rotl32(x,n)
#define ROTL64(x,n) rotl64(x,n)
#define ROTR32(x,n) rotr32(x,n)
#define ROTR64(x,n) rotr64(x,n)


// =======================
// Big-endian conversions
// =======================
#if CPU_BIG_ENDIAN

// Big-endian CPU: memory already matches the hash format
static FORCE_INLINE uint32_t BE32(const uint8_t *p) { 
    return *(const uint32_t*)p; 
}

static FORCE_INLINE uint64_t BE64(const uint8_t *p) { 
    return *(const uint64_t*)p; 
}

static FORCE_INLINE void PUT_BE32(uint8_t *p, uint32_t x) { 
    *(uint32_t*)p = x; 
}

static FORCE_INLINE void PUT_BE64(uint8_t *p, uint64_t x) { 
    *(uint64_t*)p = x; 
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
#ifdef CPU_BIG_ENDIAN

static FORCE_INLINE uint32_t TWISTED32(const uint8_t *p) {
    return  (uint32_t)p[0]       |
           ((uint32_t)p[1] << 8) |
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
    return  (uint64_t)p[0]       |
           ((uint64_t)p[1] << 8) |
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

#else

// Little-endian CPU: memory matches algorithm → no-op
static FORCE_INLINE uint32_t TWISTED32(const uint8_t *p) {
    return *(const uint32_t*)p;
}

static FORCE_INLINE uint64_t TWISTED64(const uint8_t *p) {
    return *(const uint64_t*)p;
}

static FORCE_INLINE void TWISTED_PUT32(uint8_t *p, uint32_t x) {
    *(uint32_t*)p = x;
}

static FORCE_INLINE void TWISTED_PUT64(uint8_t *p, uint64_t x) {
    *(uint64_t*)p = x;
}

#endif

#define TWISTED_LOAD32(p)    TWISTED32((const uint8_t*)(p))
#define TWISTED_STORE32(p,x) TWISTED_PUT32((uint8_t*)(p), x)
#define TWISTED_LOAD64(p)    TWISTED64((const uint8_t*)(p))
#define TWISTED_STORE64(p,x) TWISTED_PUT64((uint8_t*)(p), x)

// =======================
// Word <-> Byte conversions
// =======================
#if CPU_BIG_ENDIAN
// On big-endian CPUs, swap bytes to little-endian
static FORCE_INLINE void HASH_PACK32(uint8_t *out, const uint32_t *in, unsigned int len) {
    for (unsigned int i = 0, j = 0; j < len; i++, j += 4) {
        out[j]   = (uint8_t)(in[i] & 0xff);
        out[j+1] = (uint8_t)((in[i] >> 8) & 0xff);
        out[j+2] = (uint8_t)((in[i] >>16) & 0xff);
        out[j+3] = (uint8_t)((in[i] >>24) & 0xff);
    }
}

static FORCE_INLINE void HASH_UNPACK32(uint32_t *out, const uint8_t *in, unsigned int len) {
    for (unsigned int i = 0, j = 0; j < len; i++, j += 4) {
        out[i] = ((uint32_t)in[j]) |
                 ((uint32_t)in[j+1] << 8) |
                 ((uint32_t)in[j+2] << 16) |
                 ((uint32_t)in[j+3] << 24);
    }
}

#else
// On little-endian CPUs, memory matches the format → use direct memcpy
static FORCE_INLINE void HASH_PACK32(uint8_t *out, const uint32_t *in, unsigned int len) {
    SECURE_MEMCPY(out, in, len);
}

static FORCE_INLINE void HASH_UNPACK32(uint32_t *out, const uint8_t *in, unsigned int len) {
    SECURE_MEMCPY(out, in, len);
}
#endif

#endif // HASH_COMMON_H