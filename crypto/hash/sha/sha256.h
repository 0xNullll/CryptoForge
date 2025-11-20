#ifndef SHA2_H
#define SHA2_H

#include "../hash_common.h"
#include "../../../config/crypto_config.h"
#include "../../../utils/utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ENABLE_SHA

// ======================================
// SHA-256
// ======================================
#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];
    uint64_t len;
    uint8_t buf[SHA256_BLOCK_SIZE];
    size_t buf_len;
} ll_SHA256_CTX;

bool ll_sha256_init(ll_SHA256_CTX *ctx);
bool ll_sha256_update(ll_SHA256_CTX *ctx, const uint8_t *data, size_t len);
bool ll_sha256_final(ll_SHA256_CTX *ctx, uint8_t digest[SHA256_DIGEST_SIZE]);

static FORCE_INLINE bool ll_sha256(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE]) {
    ll_SHA256_CTX ctx;
    return ll_sha256_init(&ctx) && ll_sha256_update(&ctx, data, len) && ll_sha256_final(&ctx, digest);
}

// ======================================
// SHA-224 (truncated SHA-256)
// ======================================
#define SHA224_BLOCK_SIZE 64
#define SHA224_DIGEST_SIZE 28

typedef ll_SHA256_CTX ll_SHA224_CTX;

bool ll_sha224_init(ll_SHA224_CTX *ctx);
bool ll_sha224_update(ll_SHA224_CTX *ctx, const uint8_t *data, size_t len);
bool ll_sha224_final(ll_SHA224_CTX *ctx, uint8_t digest[SHA224_DIGEST_SIZE]);

static FORCE_INLINE bool ll_sha224(const uint8_t *data, size_t len, uint8_t digest[SHA224_DIGEST_SIZE]) {
    ll_SHA224_CTX ctx;
    return ll_sha224_init(&ctx) && ll_sha224_update(&ctx, data, len) && ll_sha224_final(&ctx, digest);
}

#endif // ENABLE_SHA

#ifdef __cplusplus
}
#endif

#endif // SHA2_H
