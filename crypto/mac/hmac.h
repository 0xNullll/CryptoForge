#ifndef HMAC_H
#define HMAC_H

#include "../evp/evp_hash.h"
#include "../evp/evp_defs.h"
#include "../evp/evp_flags.h"
#include "../evp/evp_status.h"

#include "../../config/libs.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================
// HMAC context structure
// ============================
typedef struct _ll_HMAC_CTX {
    const EVP_MD *md;                        // Low-level hash descriptor
    void *ipad_ctx;                          // Inner hash context
    void *opad_ctx;                          // Outer hash context
    uint8_t key[EVP_MAX_DEFAULT_BLOCK_SIZE]; // Pre-padded key (max block size)
    size_t key_len;
    size_t key_block_size;
    size_t out_len;

    int isFinalized;
    int isHeapAlloc; // 1 if allocated by library (heap), 0 if user stack    
} ll_HMAC_CTX;

// ============================
// HMAC low-level function prototypes
// ============================

// initializes a new HMAC_CTX for a given EVP_MD hash and key.
EVP_STATUS ll_HMAC_Init(ll_HMAC_CTX *ctx, const EVP_MD *md, const uint8_t *key, size_t key_len);

// Allocates and initializes a new HMAC_CTX for a given EVP_MD hash and key.
// Returns NULL on allocation failure.
ll_HMAC_CTX* ll_HMAC_InitAlloc(const EVP_MD *md, const uint8_t *key, size_t key_len, EVP_STATUS *status);

// Updates the HMAC with data. Can be called multiple times for streaming.
EVP_STATUS ll_HMAC_Update(ll_HMAC_CTX *ctx, const uint8_t *data, size_t data_len);

// Finalizes the HMAC and writes the digest to the output buffer.
// digest_len should be at least the hash's digest_size.
EVP_STATUS ll_HMAC_Final(ll_HMAC_CTX *ctx, uint8_t *digest, size_t digest_len);

// Frees the ll_HMAC_CTX and its internal buffers.
EVP_STATUS ll_HMAC_Free(ll_HMAC_CTX *ctx);

// Resets an ll_HMAC_CTX to its initial state with the same key and hash.
EVP_STATUS ll_HMAC_Reset(ll_HMAC_CTX *ctx);

#ifdef __cplusplus
}
#endif

#endif // HMAC_H