#ifndef SHA1_H
#define SHA1_H

#include "crypto_config.h"
#include "sha_common.h"

#ifdef __cplusplus
extern "C" {
#endif

// ======================================
//   SHA-1
// ======================================
#if ENABLE_SHA1
#define SHA1Init         TSHASH_FN(SHA1Init)
#define SHA1Update       TSHASH_FN(SHA1Update)
#define SHA1Final        TSHASH_FN(SHA1Final)
#define SHA1             TSHASH_FN(SHA1)
#define SHA1Compare      TSHASH_FN(SHA1Compare)

#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_SIZE 20

typedef struct {
   uint32_t h0,h1,h2,h3,h4;
   uint64_t len;
   uint8_t buf[SHA1_BLOCK_SIZE];
   size_t num;
} SHA1_CTX;

bool SHA1Init(SHA1_CTX *ctx);
bool SHA1Update(SHA1_CTX *ctx, const uint8_t *data, size_t len);
bool SHA1Final(SHA1_CTX *ctx, uint8_t digest[SHA1_DIGEST_SIZE]);

static FORCE_INLINE bool SHA1(const uint8_t *data, size_t len, uint8_t digest[SHA1_DIGEST_SIZE]) {
    SHA1_CTX ctx;
    return SHA1Init(&ctx) && SHA1Update(&ctx, data, len) && SHA1Final(&ctx, digest);
}

static FORCE_INLINE int SHA1Compare(const uint8_t *a, const uint8_t *b) {
    for (size_t i = 0; i < SHA1_DIGEST_SIZE; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

#endif // ENABLE_SHA1

#ifdef __cplusplus
}
#endif

#endif // SHA1_H
