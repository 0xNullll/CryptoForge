#ifndef MD5_H
#define MD5_H

#include "../hash_common.h"
#include "../../../config/crypto_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MD5_BLOCK_SIZE 64
#define MD5_DIGEST_SIZE 16

typedef struct {
    uint32_t state[4];       // A, B, C, D
    uint64_t bitlen;         // total length in bits
    uint8_t buffer[MD5_BLOCK_SIZE];
    size_t buffer_len;
} ll_MD5_CTX;

// Low-level MD5 API
bool ll_md5_init(ll_MD5_CTX *ctx);
bool ll_md5_update(ll_MD5_CTX *ctx, const uint8_t *data, size_t len);
bool ll_md5_final(ll_MD5_CTX *ctx, uint8_t digest[MD5_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif // MD5_H