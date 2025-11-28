#ifndef KMAC_H
#define KMAC_H

#include "../evp/evp_hash.h"
#include "../evp/evp_defs.h"
#include "../evp/evp_flags.h"

#include "../../utils/mem.h"
#include "../../utils/tclib_status.h"

#include "../../config/libs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    KMAC128,
    KMAC256
} ll_KMAC_TYPE;

typedef struct _ll_KMAC_CTX {
    // Core CSHAKE sponge
    void *cshake_ctx;

    // Key (raw bytes) and length
    uint8_t key[EVP_MAX_KEY_SIZE];
    size_t  key_len;

    // Requested output length in bytes
    size_t out_len;

    // Customization strings (N = function name, S = customization)
    uint8_t N[EVP_MAX_CUSTOMIZATION];
    size_t  N_len;
    uint8_t S[EVP_MAX_CUSTOMIZATION];
    size_t  S_len;

    // Bookkeeping flags
    int finalized;
    int customAbsorbed;
    int emptyNameCustom;

    // Explicit XOF flag
    int is_XOF;               // 1 = XOF, 0 = fixed-size hash
    int isHeapAlloc;          // 1 if allocated by library, 0 if user stack

    ll_KMAC_TYPE type;   // store variant internally
} ll_KMAC_CTX;

// Initializes a new ll_KMAC_CTX for a given key, output length, and optional customization strings.
TCLIB_STATUS ll_KMAC_Init(
    ll_KMAC_CTX *ctx,
    const uint8_t *key, size_t key_len,
    size_t out_len,
    const uint8_t *N, size_t N_len,
    const uint8_t *S, size_t S_len,
    int is_XOF                          // 0 = KMAC, 1 = KMACXOF
);

// Allocates and initializes a new ll_KMAC_CTX.
// Returns NULL on allocation failure.
ll_KMAC_CTX* ll_KMAC_InitAlloc(
    const uint8_t *key, size_t key_len,
    size_t out_len,
    const uint8_t *N, size_t N_len,
    const uint8_t *S, size_t S_len,
    int is_XOF,                         // 0 = KMAC, 1 = KMACXOF
    TCLIB_STATUS *status
);

// Updates the KMAC with data. Can be called multiple times for streaming.
TCLIB_STATUS ll_KMAC_Update(ll_KMAC_CTX *ctx, const uint8_t *data, size_t data_len);

// Finalizes the KMAC and writes the output to the digest buffer.
// digest_len should be at least ctx->out_len (or user-specified for XOF).
TCLIB_STATUS ll_KMAC_Final(ll_KMAC_CTX *ctx, uint8_t *digest, size_t digest_len);

// Frees the ll_KMAC_CTX and its internal buffers.
TCLIB_STATUS ll_KMAC_Free(ll_KMAC_CTX *ctx);

// Resets a KMAC context to its initial state with the same key and customization strings.
TCLIB_STATUS ll_KMAC_Reset(ll_KMAC_CTX *ctx);

// Clones a KMAC context into an existing destination context.
TCLIB_STATUS ll_KMAC_CloneCtx(
    ll_KMAC_CTX *ctx_dest,
    const ll_KMAC_CTX *ctx_src
);

// Clones a KMAC context and allocates a new heap context.
ll_KMAC_CTX* ll_KMAC_CloneCtxAlloc(
    const ll_KMAC_CTX *ctx_src,
    TCLIB_STATUS *status
);

#ifdef __cplusplus
}
#endif

#endif // KMAC_H