#ifndef SHAKE_H
#define SHAKE_H

#include "../../hash_common.h"
#include "../../../../config/crypto_config.h"
#include "../../../../utils/misc_utils.h"
#include "keccak.h"

#ifdef __cplusplus
extern "C" {
#endif

// ======================================
// SHAKE (Low-level) / RawSHAKE XOF helpers (bit-level)
// ======================================
void ll_trunc_s(const uint8_t *X, size_t Xlen, size_t s, uint8_t *out);
void ll_concat_bits(const uint8_t *X, size_t x_bits,
                    const uint8_t *Y, size_t y_bits,
                    uint8_t *out);

// ======================================
// SHAKE128
// ======================================
#define SHAKE128_BLOCK_SIZE 168
#define SHAKE128_DOMAIN 0x1F
#define SHAKE128_DEFAULT_OUT_LEN 32

typedef ll_KECCAK_CTX ll_SHAKE128_CTX;

bool ll_shake128_init(ll_SHAKE128_CTX *ctx);
bool ll_shake128_absorb(ll_SHAKE128_CTX *ctx, const uint8_t *data, size_t len);
bool ll_shake128_final(ll_SHAKE128_CTX *ctx);
bool ll_shake128_squeeze(ll_SHAKE128_CTX *ctx, uint8_t *output, size_t outlen);

// ======================================
// SHAKE256
// ======================================
#define SHAKE256_BLOCK_SIZE 136
#define SHAKE256_DOMAIN 0x1F
#define SHAKE256_DEFAULT_OUT_LEN 64

typedef ll_KECCAK_CTX ll_SHAKE256_CTX;

bool ll_shake256_init(ll_SHAKE256_CTX *ctx);
bool ll_shake256_absorb(ll_SHAKE256_CTX *ctx, const uint8_t *data, size_t len);
bool ll_shake256_final(ll_SHAKE256_CTX *ctx);
bool ll_shake256_squeeze(ll_SHAKE256_CTX *ctx, uint8_t *output, size_t outlen);

// ======================================
// RawSHAKE128
// ======================================
#define RAWSHAKE128_BLOCK_SIZE 168
#define RAWSHAKE128_DOMAIN 0x00
#define RAWSHAKE128_DEFAULT_OUT_LEN 32

typedef ll_KECCAK_CTX ll_RawSHAKE128_CTX;

bool ll_rawshake128_init(ll_RawSHAKE128_CTX *ctx);
bool ll_rawshake128_absorb(ll_RawSHAKE128_CTX *ctx, const uint8_t *data, size_t len);
bool ll_rawshake128_final(ll_RawSHAKE128_CTX *ctx);
bool ll_rawshake128_squeeze(ll_RawSHAKE128_CTX *ctx, uint8_t *output, size_t outlen);

// ======================================
// RawSHAKE256
// ======================================
#define RAWSHAKE256_BLOCK_SIZE 136
#define RAWSHAKE256_DOMAIN 0x00
#define RAWSHAKE256_DEFAULT_OUT_LEN 64

typedef ll_KECCAK_CTX ll_RawSHAKE256_CTX;

bool ll_rawshake256_init(ll_RawSHAKE256_CTX *ctx);
bool ll_rawshake256_absorb(ll_RawSHAKE256_CTX *ctx, const uint8_t *data, size_t len);
bool ll_rawshake256_final(ll_RawSHAKE256_CTX *ctx);
bool ll_rawshake256_squeeze(ll_RawSHAKE256_CTX *ctx, uint8_t *output, size_t outlen);

// ======================================
// cSHAKE128
// ======================================
#define CSHAKE128_BLOCK_SIZE 168
#define CSHAKE128_DOMAIN 0x00  // domain depends on N/S; 0x00 if empty = SHAKE128
#define CSHAKE128_DEFAULT_OUT_LEN 32

typedef struct ll_CSHAKE128_CTX {
    ll_SHAKE128_CTX *internal_ctx;   // pointer to low-level SHAKE128 context
    size_t out_len;                  // desired output length
    const uint8_t *N;                // customization string N
    size_t N_len;
    const uint8_t *S;                // customization string S
    size_t S_len;
    int finalized;                  // whether final has been called
} ll_CSHAKE128_CTX;

bool ll_cshake128_init(ll_CSHAKE128_CTX *ctx, const uint8_t *N, size_t N_len, const uint8_t *S, size_t S_len);
bool ll_cshake128_update(ll_CSHAKE128_CTX *ctx, const uint8_t *data, size_t len);
bool ll_cshake128_final(ll_CSHAKE128_CTX *ctx);
bool ll_cshake128_squeeze(ll_CSHAKE128_CTX *ctx, uint8_t *output, size_t outlen);

// ======================================
// cSHAKE256
// ======================================
#define CSHAKE256_BLOCK_SIZE 136
#define CSHAKE256_DOMAIN 0x00  // domain depends on N/S; 0x00 if empty = SHAKE256
#define CSHAKE256_DEFAULT_OUT_LEN 64

typedef struct ll_CSHAKE256_CTX {
    ll_SHAKE256_CTX *internal_ctx;   // pointer to low-level SHAKE256 context
    size_t out_len;                  // desired output length
    const uint8_t *N;                // customization string N
    size_t N_len;
    const uint8_t *S;                // customization string S
    size_t S_len;
    int finalized;                  // whether final has been called
} ll_CSHAKE256_CTX;

bool ll_cshake256_init(ll_CSHAKE256_CTX *ctx, const uint8_t *N, size_t N_len, const uint8_t *S, size_t S_len);
bool ll_cshake256_update(ll_CSHAKE256_CTX *ctx, const uint8_t *data, size_t len);
bool ll_cshake256_final(ll_CSHAKE256_CTX *ctx);
bool ll_cshake256_squeeze(ll_CSHAKE256_CTX *ctx, uint8_t *output, size_t outlen);

#ifdef __cplusplus
}
#endif

#endif // SHAKE_H