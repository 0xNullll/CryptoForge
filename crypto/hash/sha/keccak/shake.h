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
// SHAKE (Low-level) / XOF helpers (bit-level)
// ======================================
#define MAX_KEY_SIZE 512
#define MAX_CUSTOMIZATION 512
#define MAX_ENCODED_HEADER_LEN 9
                
size_t ll_right_encode_uint64(uint64_t x, uint8_t *out);

size_t ll_left_encode_uint64(uint64_t x, uint8_t *out);

size_t ll_encode_string(const uint8_t *S, size_t S_len_bytes, uint8_t *out, size_t out_len);

size_t ll_encoded_string_len(size_t S_len);

size_t ll_byte_pad(const uint8_t *S, size_t S_len, size_t w, uint8_t *out, size_t out_cap);

size_t ll_substring_bytes(const uint8_t *S, size_t S_len,
                          size_t start_idx, size_t end_idx,
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
#define CSHAKE128_DOMAIN 0x04  // domain separation for cSHAKE128 when N or S non-empty
#define CSHAKE128_DEFAULT_OUT_LEN 32


typedef struct _ll_CSHAKE128_CTX {
    ll_SHAKE128_CTX internal_ctx;
    size_t out_len;                  // Desired output length in bytes or bits, depending on usage
    uint8_t N[MAX_CUSTOMIZATION]; // Customization string N (can be empty)
    size_t N_len;                    // Length of N in bytes
    uint8_t S[MAX_CUSTOMIZATION]; // Customization string S (can be empty)
    size_t S_len;                    // Length of S in bytes
    int finalized;                   // Flag indicating if finalization has been performed
    int customAbsorbed;
    uint8_t emptyNameCustom;
    int xof_mode;
} ll_CSHAKE128_CTX;

bool ll_cshake128_init(ll_CSHAKE128_CTX *ctx,
                       const uint8_t *N, size_t N_len,
                       const uint8_t *S, size_t S_len);

bool ll_cshake128_absorb(ll_CSHAKE128_CTX *ctx, const uint8_t *data, size_t len);

bool ll_cshake128_final(ll_CSHAKE128_CTX *ctx);

bool ll_cshake128_squeeze(ll_CSHAKE128_CTX *ctx, uint8_t *output, size_t outlen);

// ======================================
// cSHAKE256
// ======================================
#define CSHAKE256_BLOCK_SIZE 136
#define CSHAKE256_DOMAIN 0x04  // domain separation for cSHAKE256 when N or S non-empty
#define CSHAKE256_DEFAULT_OUT_LEN 64

typedef struct _ll_CSHAKE256_CTX {
    ll_SHAKE256_CTX internal_ctx;
    size_t out_len;                  // Desired output length in bytes or bits, depending on usage
    uint8_t N[MAX_CUSTOMIZATION]; // Customization string N (can be empty)
    size_t N_len;                    // Length of N in bytes
    uint8_t S[MAX_CUSTOMIZATION]; // Customization string S (can be empty)
    size_t S_len;                    // Length of S in bytes
    int finalized;                   // Flag indicating if finalization has been performed
    int customAbsorbed;
    uint8_t emptyNameCustom;
    int xof_mode;
} ll_CSHAKE256_CTX;

bool ll_cshake256_init(ll_CSHAKE256_CTX *ctx,
                       const uint8_t *N, size_t N_len,
                       const uint8_t *S, size_t S_len);

bool ll_cshake256_absorb(ll_CSHAKE256_CTX *ctx, const uint8_t *data, size_t len);

bool ll_cshake256_final(ll_CSHAKE256_CTX *ctx);

bool ll_cshake256_squeeze(ll_CSHAKE256_CTX *ctx, uint8_t *output, size_t outlen);

#ifdef __cplusplus
}
#endif

#endif // SHAKE_H