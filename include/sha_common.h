#ifndef SHA_COMMON_H
#define SHA_COMMON_H

#include "libs.h"
#include "crypto_config.h"
#include "utils.h"

// ----------------------
// Bit rotation helpers
// ----------------------
static FORCE_INLINE uint32_t rotl32(uint32_t x, uint32_t n) {
    n &= 31;
    return (x << n) | (x >> (32 - n));
}

static FORCE_INLINE uint64_t rotl64(uint64_t x, uint64_t n) {
    n &= 63;
    return ((x) << (n)) | ((x) >> (64 - (n)));
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

// ----------------------
// Big-endian conversions
// ----------------------

// ==============================================================
// SHA-1 / SHA-2 Big-endian helpers (32/64-bit)
// For use with SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
// ==============================================================

// 32-bit (SHA-1 / SHA-256 / SHA-224)
static FORCE_INLINE uint32_t BE32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |
           ((uint32_t)p[3]);
}

// 64-bit (SHA-512 / SHA-384)
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

// Write back to memory (big-endian)
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

// ----------------------
// SHA-1 / SHA-2 load/store macros (big-endian)
// ----------------------
#define SHA_LOAD32(p)    BE32((const uint8_t*)(p))
#define SHA_STORE32(p,x) PUT_BE32((uint8_t*)(p), x)
#define SHA_LOAD64(p)    BE64((const uint8_t*)(p))
#define SHA_STORE64(p,x) PUT_BE64((uint8_t*)(p), x)


// ==============================================================
// Keccak / SHA-3 Big-endian helpers (32/64-bit)
// For use with Keccak, SHA3-224, SHA3-256, SHA3-384, SHA3-512
// ==============================================================
#ifdef CPU_BIG_ENDIAN
// Big-endian CPU: swap bytes manually for Keccak
static FORCE_INLINE uint32_t KECCAK_BE32(const uint8_t *p) {
    return  (uint32_t)p[0]       |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static FORCE_INLINE void KECCAK_PUT_BE32(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)(x      );
    p[1] = (uint8_t)(x >>  8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
}

static FORCE_INLINE uint64_t KECCAK_BE64(const uint8_t *p) {
    return  (uint64_t)p[0]       |
           ((uint64_t)p[1] << 8) |
           ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
}

static FORCE_INLINE void KECCAK_PUT_BE64(uint8_t *p, uint64_t x) {
    p[0] = (uint8_t)(x      );
    p[1] = (uint8_t)(x >>  8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
    p[4] = (uint8_t)(x >> 32);
    p[5] = (uint8_t)(x >> 40);
    p[6] = (uint8_t)(x >> 48);
    p[7] = (uint8_t)(x >> 56);
}

#else
// Little-endian CPU: memory matches Keccak → no operation needed
static FORCE_INLINE uint32_t KECCAK_BE32(const uint8_t *p) {
    return *(const uint32_t*)p;
}

static FORCE_INLINE void KECCAK_PUT_BE32(uint8_t *p, uint32_t x) {
    *(uint32_t*)p = x;
}

static FORCE_INLINE uint64_t KECCAK_BE64(const uint8_t *p) {
    return *(const uint64_t*)p;
}

static FORCE_INLINE void KECCAK_PUT_BE64(uint8_t *p, uint64_t x) {
    *(uint64_t*)p = x;
}
#endif

// ----------------------
// Keccak / SHA-3 load/store macros (big-endian)
// ----------------------
#define KECCAK_LOAD32(p)    KECCAK_BE32((const uint8_t*)(p))
#define KECCAK_STORE32(p,x) KECCAK_PUT_BE32((uint8_t*)(p), x)
#define KECCAK_LOAD64(p)    KECCAK_BE64((const uint8_t*)(p))
#define KECCAK_STORE64(p,x) KECCAK_PUT_BE64((uint8_t*)(p), x)

#endif  // SHA_COMMON_H 