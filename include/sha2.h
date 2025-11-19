#ifndef SHA2_H
#define SHA2_H

#include "crypto_config.h"
#include "sha_common.h"
#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

// ======================================
// SHA-256
// ======================================
#if ENABLE_SHA256
#define SHA256Init         TSHASH_FN(SHA256Init)
#define SHA256Update       TSHASH_FN(SHA256Update)
#define SHA256Final        TSHASH_FN(SHA256Final)
#define SHA256             TSHASH_FN(SHA256)

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

typedef struct {
   uint32_t state[8];
   uint64_t len;
   uint8_t buf[SHA256_BLOCK_SIZE];
   size_t buf_len;
} SHA256_CTX;

bool SHA256Init(SHA256_CTX *ctx);
bool SHA256Update(SHA256_CTX *ctx, const uint8_t *data, size_t len);
bool SHA256Final(SHA256_CTX *ctx, uint8_t digest[SHA256_DIGEST_SIZE]);

static FORCE_INLINE bool SHA256(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE]){
    SHA256_CTX ctx;
    return SHA256Init(&ctx) && SHA256Update(&ctx, data, len) && SHA256Final(&ctx, digest);
}

#endif // ENABLE_SHA256

// ======================================
// SHA-224 (truncated SHA-256)
// ======================================
#if ENABLE_SHA224
#define SHA224Init         TSHASH_FN(SHA224Init)
#define SHA224Update       TSHASH_FN(SHA224Update)
#define SHA224Final        TSHASH_FN(SHA224Final)
#define SHA224             TSHASH_FN(SHA224)

#define SHA224_BLOCK_SIZE 64
#define SHA224_DIGEST_SIZE 28

typedef SHA256_CTX SHA224_CTX;

bool SHA224Init(SHA224_CTX *ctx);
bool SHA224Update(SHA224_CTX *ctx, const uint8_t *data, size_t len);
bool SHA224Final(SHA224_CTX *ctx, uint8_t digest[SHA224_DIGEST_SIZE]);

static FORCE_INLINE bool SHA224(const uint8_t *data, size_t len, uint8_t digest[SHA224_DIGEST_SIZE]) {
    SHA224_CTX ctx;
    return SHA224Init(&ctx) && SHA224Update(&ctx, data, len) && SHA224Final(&ctx, digest);   
}


#endif // ENABLE_SHA224

// ======================================
// SHA-512
// ======================================
#if ENABLE_SHA512
#define SHA512Init         TSHASH_FN(SHA512Init)
#define SHA512Update       TSHASH_FN(SHA512Update)
#define SHA512Final        TSHASH_FN(SHA512Final)
#define SHA512             TSHASH_FN(SHA512)

#define SHA512_BLOCK_SIZE 128
#define SHA512_DIGEST_SIZE 64

typedef struct {
   uint64_t state[8];
   uint64_t Nl, Nh;
   uint8_t buf[SHA512_BLOCK_SIZE];
   size_t buf_len;
} SHA512_CTX;

bool SHA512Init(SHA512_CTX *ctx);
bool SHA512Update(SHA512_CTX *ctx, const uint8_t *data, size_t len);
bool SHA512Final(SHA512_CTX *ctx, uint8_t digest[SHA512_DIGEST_SIZE]);

static FORCE_INLINE bool SHA512(const uint8_t *data, size_t len, uint8_t digest[SHA512_DIGEST_SIZE]) {
    SHA512_CTX ctx;
    return SHA512Init(&ctx) && SHA512Update(&ctx, data, len) && SHA512Final(&ctx, digest);
}

#endif // ENABLE_SHA512

// ======================================
// SHA-384 (truncated SHA-512)
// ======================================
#if ENABLE_SHA384
#define SHA384Init         TSHASH_FN(SHA384Init)
#define SHA384Update       TSHASH_FN(SHA384Update)
#define SHA384Final        TSHASH_FN(SHA384Final)
#define SHA384             TSHASH_FN(SHA384)

#define SHA384_BLOCK_SIZE 128
#define SHA384_DIGEST_SIZE 48

typedef SHA512_CTX SHA384_CTX;

bool SHA384Init(SHA384_CTX *ctx);
bool SHA384Update(SHA384_CTX *ctx, const uint8_t *data, size_t len);
bool SHA384Final(SHA384_CTX *ctx, uint8_t digest[SHA384_DIGEST_SIZE]);

static FORCE_INLINE bool SHA384(const uint8_t *data, size_t len, uint8_t digest[SHA384_DIGEST_SIZE]) {
    SHA384_CTX ctx;
    return SHA384Init(&ctx) && SHA384Update(&ctx, data, len) && SHA384Final(&ctx, digest);   
}

#endif // ENABLE_SHA384

// ======================================
// SHA-512/224 (truncated SHA-512)
// ======================================
#if ENABLE_SHA512_224
#define SHA512_224Init         TSHASH_FN(SHA512_224Init)
#define SHA512_224Update       TSHASH_FN(SHA512_224Update)
#define SHA512_224Final        TSHASH_FN(SHA512_224Final)
#define SHA512_224             TSHASH_FN(SHA512_224)

#define SHA512_224_BLOCK_SIZE 128
#define SHA512_224_DIGEST_SIZE 28

typedef SHA512_CTX SHA512_224_CTX;

bool SHA512_224Init(SHA512_224_CTX *ctx);
bool SHA512_224Update(SHA512_224_CTX *ctx, const uint8_t *data, size_t len);
bool SHA512_224Final(SHA512_224_CTX *ctx, uint8_t digest[SHA512_224_DIGEST_SIZE]);

static FORCE_INLINE bool SHA512_224(const uint8_t *data, size_t len, uint8_t digest[SHA512_224_DIGEST_SIZE]) {
    SHA512_224_CTX ctx;
    return SHA512_224Init(&ctx) && SHA512_224Update(&ctx, data, len) && SHA512_224Final(&ctx, digest);
}

#endif // ENABLE_SHA512_224

// ======================================
// SHA-512/256 (truncated SHA-512)
// ======================================
#if ENABLE_SHA512_256
#define SHA512_256Init         TSHASH_FN(SHA512_256Init)
#define SHA512_256Update       TSHASH_FN(SHA512_256Update)
#define SHA512_256Final        TSHASH_FN(SHA512_256Final)
#define SHA512_256             TSHASH_FN(SHA512_256)

#define SHA512_256_BLOCK_SIZE 128
#define SHA512_256_DIGEST_SIZE 32

typedef SHA512_CTX SHA512_256_CTX;

bool SHA512_256Init(SHA512_256_CTX *ctx);
bool SHA512_256Update(SHA512_256_CTX *ctx, const uint8_t *data, size_t len);
bool SHA512_256Final(SHA512_256_CTX *ctx, uint8_t digest[SHA512_256_DIGEST_SIZE]);

static FORCE_INLINE bool SHA512_256(const uint8_t *data, size_t len, uint8_t digest[SHA512_256_DIGEST_SIZE]) {
    SHA512_256_CTX ctx;
    return SHA512_256Init(&ctx) && SHA512_256Update(&ctx, data, len) && SHA512_256Final(&ctx, digest);
}

#endif // ENABLE_SHA512_256

#ifdef __cplusplus
}
#endif

#endif // SHA2_H