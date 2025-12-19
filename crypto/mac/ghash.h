#ifndef GHASH_H
#define GHASH_H

#include "../../../utils/mem.h"
#include "../../../utils/misc_utils.h"
#include "../../../config/libs.h"
#include "aes_core.h"

#ifdef __cplusplus
extern "C" {
#endif

//
// GHASH: Polynomial hash over GF(2^128) used in AES-GCM/GMAC
// H = hash subkey (from AES key), X = input data, Z = output tag
//

typedef struct {
    uint8_t H[AES_BLOCK_SIZE];   // Hash subkey
    uint8_t Z[AES_BLOCK_SIZE];   // Accumulator
} ll_GHASH_CTX;

// Initialize GHASH context with hash subkey H
void ll_GHASH_Init(ll_GHASH_CTX *ctx, const uint8_t H[AES_BLOCK_SIZE]);

// Process input data X of length len (multiple of 16 bytes)
void ll_GHASH_Update(ll_GHASH_CTX *ctx, const uint8_t *X, size_t len);

// Finalize GHASH, store result in out (16 bytes)
void ll_GHASH_Final(ll_GHASH_CTX *ctx, uint8_t out[AES_BLOCK_SIZE]);

#ifdef __cplusplus
}
#endif

#endif // GHASH_H
