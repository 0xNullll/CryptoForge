#ifndef KECCAK_H
#define KECCAK_H

#include "crypto_config.h"
#include "sha_common.h"
#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ENABLE_KECCAK_CORE
#define KeccakInit      TSHASH_FN(KeccakInit)
#define keccakP         TSHASH_FN(keccakP)
#define KeccakAbsorb    TSHASH_FN(KeccakAbsorb)
#define KeccakFinal     TSHASH_FN(KeccakFinal)
#define KeccakSqueeze   TSHASH_FN(KeccakSqueeze)
#define Keccak          TSHASH_FN(Keccak)

#define KECCAK_BLOCK_SIZE 200

typedef struct {
    uint64_t state[5][5];
    uint8_t buf[KECCAK_BLOCK_SIZE];
    size_t buf_len;
    size_t rate;
    uint8_t suffix;
    int finalized;
} KECCAK_CTX;


bool KeccakInit(KECCAK_CTX *ctx, size_t rate, uint8_t suffix);
bool keccakP(uint64_t state[5][5], unsigned int w, unsigned int nr);
bool KeccakAbsorb(KECCAK_CTX *ctx, const uint8_t *data, size_t len);
bool KeccakFinal(KECCAK_CTX *ctx);
bool KeccakSqueeze(KECCAK_CTX *ctx, uint8_t *output, size_t outlen);

static FORCE_INLINE bool Keccak(
    const uint8_t *data, size_t len,
    uint8_t *digest, size_t outlen,
    size_t rate, uint8_t suffix) {
    
    KECCAK_CTX ctx;
    return KeccakInit(&ctx, rate, suffix)
        && KeccakAbsorb(&ctx, data, len)
        && KeccakFinal(&ctx)
        && KeccakSqueeze(&ctx, digest, outlen);
}

#endif // ENABLE_KECCAK_CORE

#ifdef __cplusplus
}
#endif

#endif // KECCAK_H