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

#define LL_KMAC_TYPE_IS_VALID(type) \
    ((type) == KMAC128 || (type) == KMAC256 || \
     (type) == KMACXOF128 || (type) == KMACXOF256)

#define LL_KMAC_IS_128(ctx) ((ctx)->type == KMAC128 || (ctx)->type == KMACXOF128)
#define LL_KMAC_IS_XOF(ctx) ((ctx)->type == KMACXOF128 || (ctx)->type == KMACXOF256)

typedef enum {
    KMAC128      = EVP_CAT_MAC | 0x0002,
    KMAC256      = EVP_CAT_MAC | 0x0003,
    KMACXOF128   = EVP_CAT_MAC | 0x0004,
    KMACXOF256   = EVP_CAT_MAC | 0x0005
} ll_KMAC_TYPE;

typedef struct _ll_KMAC_CTX {
    // Core CSHAKE sponge context
    void *cshake_ctx;

    // Key (raw bytes) and length
    uint8_t key[MAX_KEY_SIZE];
    size_t  key_len;

    // Requested output length in bytes (L in the spec)
    size_t out_len;

    // Customization strings
    uint8_t S[MAX_CUSTOMIZATION]; // Customization string (can be empty)
    size_t  S_len;

    // Bookkeeping flags
    int isFinalized;        // 1 if finalization done
    int customAbsorbed;     // 1 if N||S absorbed
    int emptyNameCustom;    // 1 if S are empty

    int isXOF;
    int isHeapAlloc;        // 1 if allocated on heap, 0 if stack

    // KMAC variant
    ll_KMAC_TYPE type;      // e.g., KMAC128, KMAC256, KMACXOF128, KMACXOF256
} ll_KMAC_CTX;

// Initializes a new ll_KMAC_CTX for a given key, output length, and optional customization strings.
TCLIB_STATUS ll_KMAC_Init(
    ll_KMAC_CTX *ctx,
    const uint8_t *key, size_t key_len,
    const uint8_t *S, size_t S_len,
    ll_KMAC_TYPE type      // varients: KMAC128, KMAC256, KMACXOF128, KMACXOF256
);

// Allocates and initializes a new ll_KMAC_CTX and Returns NULL on allocation failure.
ll_KMAC_CTX* ll_KMAC_InitAlloc(
    const uint8_t *key, size_t key_len,
    const uint8_t *S, size_t S_len,
    ll_KMAC_TYPE type,      // varients: KMAC128, KMAC256, KMACXOF128, KMACXOF256
    TCLIB_STATUS *status
);

// Updates the KMAC with data. Can be called multiple times for streaming.
TCLIB_STATUS ll_KMAC_Update(ll_KMAC_CTX *ctx, const uint8_t *data, size_t data_len);

// Finalizes the KMAC if not finalized already and writes the output to the digest buffer
TCLIB_STATUS ll_KMAC_Final(ll_KMAC_CTX *ctx, uint8_t *digest, size_t digest_len);

// Resets a KMAC context to its initial state with the same key and customization strings.
TCLIB_STATUS ll_KMAC_Free(ll_KMAC_CTX *ctx);

// Frees the ll_KMAC_CTX and its internal buffers.
TCLIB_STATUS ll_KMAC_FreeAlloc(ll_KMAC_CTX **p_ctx);

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