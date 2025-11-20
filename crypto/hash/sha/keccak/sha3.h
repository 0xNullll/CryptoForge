#ifndef SHA3_H
#define SHA3_H

#include "../../hash_common.h"
#include "../../../../config/crypto_config.h"
#include "../../../../utils/utils.h"
#include "keccak.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ENABLE_SHA || ENABLE_SHA3

// ======================================
// SHA3 (Low-level wrappers around Keccak)
// ======================================

// ======================================
// SHA3-224
// ======================================
#define SHA3_224_BLOCK_SIZE 144
#define SHA3_224_DIGEST_SIZE 28
#define SHA3_224_DOMAIN 0x06

typedef ll_KECCAK_CTX ll_sha3_224_CTX;

bool ll_sha3_224_init(ll_sha3_224_CTX *ctx);
bool ll_sha3_224_absorb(ll_sha3_224_CTX *ctx, const uint8_t *data, size_t len);
bool ll_sha3_224_final(ll_sha3_224_CTX *ctx);
bool ll_sha3_224_squeeze(ll_sha3_224_CTX *ctx, uint8_t *output, size_t outlen);

static FORCE_INLINE bool ll_sha3_224(
    const uint8_t *data, size_t len, uint8_t digest[SHA3_224_DIGEST_SIZE]) {
    
    ll_sha3_224_CTX ctx;
    return ll_sha3_224_init(&ctx)
        && ll_sha3_224_absorb(&ctx, data, len)
        && ll_sha3_224_final(&ctx)
        && ll_sha3_224_squeeze(&ctx, digest, SHA3_224_DIGEST_SIZE);
}

// ======================================
// SHA3-256
// ======================================
#define SHA3_256_BLOCK_SIZE 136
#define SHA3_256_DIGEST_SIZE 32
#define SHA3_256_DOMAIN 0x06

typedef ll_KECCAK_CTX ll_sha3_256_CTX;

bool ll_sha3_256_init(ll_sha3_256_CTX *ctx);
bool ll_sha3_256_absorb(ll_sha3_256_CTX *ctx, const uint8_t *data, size_t len);
bool ll_sha3_256_final(ll_sha3_256_CTX *ctx);
bool ll_sha3_256_squeeze(ll_sha3_256_CTX *ctx, uint8_t *output, size_t outlen);

static FORCE_INLINE bool ll_sha3_256(
    const uint8_t *data, size_t len, uint8_t digest[SHA3_256_DIGEST_SIZE]) {
    
    ll_sha3_256_CTX ctx;
    return ll_sha3_256_init(&ctx)
        && ll_sha3_256_absorb(&ctx, data, len)
        && ll_sha3_256_final(&ctx)
        && ll_sha3_256_squeeze(&ctx, digest, SHA3_256_DIGEST_SIZE);
}

// ======================================
// SHA3-384
// ======================================
#define SHA3_384_BLOCK_SIZE 104
#define SHA3_384_DIGEST_SIZE 48
#define SHA3_384_DOMAIN 0x06

typedef ll_KECCAK_CTX ll_sha3_384_CTX;

bool ll_sha3_384_init(ll_sha3_384_CTX *ctx);
bool ll_sha3_384_absorb(ll_sha3_384_CTX *ctx, const uint8_t *data, size_t len);
bool ll_sha3_384_final(ll_sha3_384_CTX *ctx);
bool ll_sha3_384_squeeze(ll_sha3_384_CTX *ctx, uint8_t *output, size_t outlen);

static FORCE_INLINE bool ll_sha3_384(
    const uint8_t *data, size_t len, uint8_t digest[SHA3_384_DIGEST_SIZE]) {
    
    ll_sha3_384_CTX ctx;
    return ll_sha3_384_init(&ctx)
        && ll_sha3_384_absorb(&ctx, data, len)
        && ll_sha3_384_final(&ctx)
        && ll_sha3_384_squeeze(&ctx, digest, SHA3_384_DIGEST_SIZE);
}

// ======================================
// SHA3-512
// ======================================
#define SHA3_512_BLOCK_SIZE 72
#define SHA3_512_DIGEST_SIZE 64
#define SHA3_512_DOMAIN 0x06

typedef ll_KECCAK_CTX ll_sha3_512_CTX;

bool ll_sha3_512_init(ll_sha3_512_CTX *ctx);
bool ll_sha3_512_absorb(ll_sha3_512_CTX *ctx, const uint8_t *data, size_t len);
bool ll_sha3_512_final(ll_sha3_512_CTX *ctx);
bool ll_sha3_512_squeeze(ll_sha3_512_CTX *ctx, uint8_t *output, size_t outlen);

static FORCE_INLINE bool ll_sha3_512(
    const uint8_t *data, size_t len, uint8_t digest[SHA3_512_DIGEST_SIZE]) {
    
    ll_sha3_512_CTX ctx;
    return ll_sha3_512_init(&ctx)
        && ll_sha3_512_absorb(&ctx, data, len)
        && ll_sha3_512_final(&ctx)
        && ll_sha3_512_squeeze(&ctx, digest, SHA3_512_DIGEST_SIZE);
}

#endif // ENABLE_SHA || ENABLE_SHA3

#ifdef __cplusplus
}
#endif

#endif // SHA3_H