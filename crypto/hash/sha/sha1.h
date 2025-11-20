#ifndef SHA1_H
#define SHA1_H

#include "../hash_common.h"
#include "../../../config/crypto_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ENABLE_SHA

// ======================================
// SHA-1
// ======================================
#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_SIZE 20

typedef struct {
   uint32_t h0, h1, h2, h3, h4;
   uint64_t len;
   uint8_t buf[SHA1_BLOCK_SIZE];
   size_t num;
} ll_SHA1_CTX;

bool ll_sha1_init(ll_SHA1_CTX *ctx);
bool ll_sha1_update(ll_SHA1_CTX *ctx, const uint8_t *data, size_t len);
bool ll_sha1_final(ll_SHA1_CTX *ctx, uint8_t digest[SHA1_DIGEST_SIZE]);

static FORCE_INLINE bool ll_sha1(const uint8_t *data, size_t len, uint8_t digest[SHA1_DIGEST_SIZE]) {
    ll_SHA1_CTX ctx;
    return ll_sha1_init(&ctx) && ll_sha1_update(&ctx, data, len) && ll_sha1_final(&ctx, digest);
}

#endif // ENABLE_SHA

#ifdef __cplusplus
}
#endif

#endif // SHA1_H