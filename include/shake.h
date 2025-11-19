#ifndef SHAKE_H
#define SHAKE_H

#include "crypto_config.h"
#include "sha_common.h"
#include "keccak.h"

#ifdef __cplusplus
extern "C" {
#endif

// ======================================
// Helper functions for SHAKE / RawSHAKE XOF
// Only included if ENABLE_SHAKE_XOF is set
// ======================================
#if ENABLE_SHAKE_XOF

void Trunc_s(const uint8_t *X, size_t Xlen, size_t s, uint8_t *out);

void concat_bits(const uint8_t *X, size_t x_bits,
                        const uint8_t *Y, size_t y_bits,
                        uint8_t *out);

#endif // ENABLE_SHAKE_XOF

// ======================================
// SHAKE128
// ======================================
#if ENABLE_SHAKE128
#define SHAKE128Init         TSHASH_FN(SHAKE128Init)
#define SHAKE128Absorb       TSHASH_FN(SHAKE128Absorb)
#define SHAKE128Final        TSHASH_FN(SHAKE128Final)
#define SHAKE128Squeeze      TSHASH_FN(SHAKE128Squeeze)
#define SHAKE128             TSHASH_FN(SHAKE128)
#define SHAKE128Compare      TSHASH_FN(SHAKE128Compare)

#define SHAKE128_BLOCK_SIZE 168
#define SHAKE128_DOMAIN 0x1F

typedef KECCAK_CTX SHAKE128_CTX;

bool SHAKE128Init(SHAKE128_CTX *ctx);
bool SHAKE128Absorb(SHAKE128_CTX *ctx, const uint8_t *data, size_t len);
bool SHAKE128Final(SHAKE128_CTX *ctx);
bool SHAKE128Squeeze(SHAKE128_CTX *ctx, uint8_t *output, size_t outlen);
bool SHAKE128(const uint8_t *data, size_t len, uint8_t *digest, size_t outlen);

static FORCE_INLINE int SHAKE128Compare(const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

#endif // ENABLE_SHAKE128

// ======================================
// SHAKE256
// ======================================
#if ENABLE_SHAKE256
#define SHAKE256Init         TSHASH_FN(SHAKE256Init)
#define SHAKE256Absorb       TSHASH_FN(SHAKE256Absorb)
#define SHAKE256Final        TSHASH_FN(SHAKE256Final)
#define SHAKE256Squeeze      TSHASH_FN(SHAKE256Squeeze)
#define SHAKE256             TSHASH_FN(SHAKE256)
#define SHAKE256Compare      TSHASH_FN(SHAKE256Compare)

#define SHAKE256_BLOCK_SIZE 136
#define SHAKE256_DOMAIN 0x1F

typedef KECCAK_CTX SHAKE256_CTX;

bool SHAKE256Init(SHAKE256_CTX *ctx);
bool SHAKE256Absorb(SHAKE256_CTX *ctx, const uint8_t *data, size_t len);
bool SHAKE256Final(SHAKE256_CTX *ctx);
bool SHAKE256Squeeze(SHAKE256_CTX *ctx, uint8_t *output, size_t outlen);
bool SHAKE256(const uint8_t *data, size_t len, uint8_t *digest, size_t outlen);

static FORCE_INLINE int SHAKE256Compare(const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

#endif // ENABLE_SHAKE256

// ======================================
// RawSHAKE128
// ======================================
#if ENABLE_RAWSHAKE128
#define RawSHAKE128Init         TSHASH_FN(RawSHAKE128Init)
#define RawSHAKE128Absorb       TSHASH_FN(RawSHAKE128Absorb)
#define RawSHAKE128Final        TSHASH_FN(RawSHAKE128Final)
#define RawSHAKE128Squeeze      TSHASH_FN(RawSHAKE128Squeeze)
#define RawSHAKE128             TSHASH_FN(RawSHAKE128)
#define RawSHAKE128Compare      TSHASH_FN(RawSHAKE128Compare)

#define RAWSHAKE128_BLOCK_SIZE 168
#define RAWSHAKE128_DOMAIN 0x00

typedef KECCAK_CTX RawSHAKE128_CTX;

bool RawSHAKE128Init(RawSHAKE128_CTX *ctx);
bool RawSHAKE128Absorb(RawSHAKE128_CTX *ctx, const uint8_t *data, size_t len);
bool RawSHAKE128Final(RawSHAKE128_CTX *ctx);
bool RawSHAKE128Squeeze(RawSHAKE128_CTX *ctx, uint8_t *output, size_t outlen);
bool RawSHAKE128(const uint8_t *data, size_t len, uint8_t *digest, size_t outlen);

static FORCE_INLINE int RawSHAKE128Compare(const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

#endif // ENABLE_RAWSHAKE128

// ======================================
// RawSHAKE256
// ======================================
#if ENABLE_RAWSHAKE256
#define RawSHAKE256Init         TSHASH_FN(RawSHAKE256Init)
#define RawSHAKE256Absorb       TSHASH_FN(RawSHAKE256Absorb)
#define RawSHAKE256Final        TSHASH_FN(RawSHAKE256Final)
#define RawSHAKE256Squeeze      TSHASH_FN(RawSHAKE256Squeeze)
#define RawSHAKE256             TSHASH_FN(RawSHAKE256)
#define RawSHAKE256Compare      TSHASH_FN(RawSHAKE256Compare)

#define RAWSHAKE256_BLOCK_SIZE 136
#define RAWSHAKE256_DOMAIN 0x00

typedef KECCAK_CTX RawSHAKE256_CTX;

bool RawSHAKE256Init(RawSHAKE256_CTX *ctx);
bool RawSHAKE256Absorb(RawSHAKE256_CTX *ctx, const uint8_t *data, size_t len);
bool RawSHAKE256Final(RawSHAKE256_CTX *ctx);
bool RawSHAKE256Squeeze(RawSHAKE256_CTX *ctx, uint8_t *output, size_t outlen);
bool RawSHAKE256(const uint8_t *data, size_t len, uint8_t *digest, size_t outlen);

static FORCE_INLINE int RawSHAKE256Compare(const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

#endif // ENABLE_RAWSHAKE256

#ifdef __cplusplus
}
#endif

#endif // SHAKE_H