#ifndef SHA3_H
#define SHA3_H

#include "crypto_config.h"
#include "sha_common.h"
#include "keccak.h"

#ifdef __cplusplus
extern "C" {
#endif

// ======================================
// SHA3-224
// ======================================
#if ENABLE_SHA3_224
#define SHA3_224Init         TSHASH_FN(SHA3_224Init)
#define SHA3_224Absorb       TSHASH_FN(SHA3_224Absorb)
#define SHA3_224Final        TSHASH_FN(SHA3_224Final)
#define SHA3_224Squeeze      TSHASH_FN(SHA3_224Squeeze)
#define SHA3_224             TSHASH_FN(SHA3_224)

#define SHA3_224_BLOCK_SIZE 144
#define SHA3_224_DIGEST_SIZE 28
#define SHA3_224_DOMAIN 0x06

typedef KECCAK_CTX SHA3_224_CTX;

bool SHA3_224Init(SHA3_224_CTX *ctx);
bool SHA3_224Absorb(SHA3_224_CTX *ctx, const uint8_t *data, size_t len);
bool SHA3_224Final(SHA3_224_CTX *ctx);
bool SHA3_224Squeeze(SHA3_224_CTX *ctx, uint8_t *output, size_t outlen);
bool SHA3_224(const uint8_t *data, size_t len, uint8_t digest[SHA3_224_DIGEST_SIZE]);

#endif // ENABLE_SHA3_224

// ======================================
// SHA3-256
// ======================================
#if ENABLE_SHA3_256
#define SHA3_256Init         TSHASH_FN(SHA3_256Init)
#define SHA3_256Absorb       TSHASH_FN(SHA3_256Absorb)
#define SHA3_256Final        TSHASH_FN(SHA3_256Final)
#define SHA3_256Squeeze      TSHASH_FN(SHA3_256Squeeze)
#define SHA3_256             TSHASH_FN(SHA3_256)

#define SHA3_256_BLOCK_SIZE 136
#define SHA3_256_DIGEST_SIZE 32
#define SHA3_256_DOMAIN 0x06

typedef KECCAK_CTX SHA3_256_CTX;

bool SHA3_256Init(SHA3_256_CTX *ctx);
bool SHA3_256Absorb(SHA3_256_CTX *ctx, const uint8_t *data, size_t len);
bool SHA3_256Final(SHA3_256_CTX *ctx);
bool SHA3_256Squeeze(SHA3_256_CTX *ctx, uint8_t *output, size_t outlen);
bool SHA3_256(const uint8_t *data, size_t len, uint8_t digest[SHA3_256_DIGEST_SIZE]);

#endif // ENABLE_SHA3_256

// ======================================
// SHA3-384
// ======================================
#if ENABLE_SHA3_384
#define SHA3_384Init         TSHASH_FN(SHA3_384Init)
#define SHA3_384Absorb       TSHASH_FN(SHA3_384Absorb)
#define SHA3_384Final        TSHASH_FN(SHA3_384Final)
#define SHA3_384Squeeze      TSHASH_FN(SHA3_384Squeeze)
#define SHA3_384             TSHASH_FN(SHA3_384)

#define SHA3_384_BLOCK_SIZE 104
#define SHA3_384_DIGEST_SIZE 48
#define SHA3_384_DOMAIN 0x06

typedef KECCAK_CTX SHA3_384_CTX;

bool SHA3_384Init(SHA3_384_CTX *ctx);
bool SHA3_384Absorb(SHA3_384_CTX *ctx, const uint8_t *data, size_t len);
bool SHA3_384Final(SHA3_384_CTX *ctx);
bool SHA3_384Squeeze(SHA3_384_CTX *ctx, uint8_t *output, size_t outlen);
bool SHA3_384(const uint8_t *data, size_t len, uint8_t digest[SHA3_384_DIGEST_SIZE]);

#endif // ENABLE_SHA3_384

// ======================================
// SHA3-512
// ====================================== 
#if ENABLE_SHA3_512
#define SHA3_512Init         TSHASH_FN(SHA3_512Init)
#define SHA3_512Absorb       TSHASH_FN(SHA3_512Absorb)
#define SHA3_512Final        TSHASH_FN(SHA3_512Final)
#define SHA3_512Squeeze      TSHASH_FN(SHA3_512Squeeze)
#define SHA3_512             TSHASH_FN(SHA3_512)

#define SHA3_512_BLOCK_SIZE 72
#define SHA3_512_DIGEST_SIZE 64
#define SHA3_512_DOMAIN 0x06

typedef KECCAK_CTX SHA3_512_CTX;

bool SHA3_512Init(SHA3_512_CTX *ctx);
bool SHA3_512Absorb(SHA3_512_CTX *ctx, const uint8_t *data, size_t len);
bool SHA3_512Final(SHA3_512_CTX *ctx);
bool SHA3_512Squeeze(SHA3_512_CTX *ctx, uint8_t *output, size_t outlen);
bool SHA3_512(const uint8_t *data, size_t len, uint8_t digest[SHA3_512_DIGEST_SIZE]);

#endif // ENABLE_SHA3_512

#ifdef __cplusplus
}
#endif

#endif // SHA3_H