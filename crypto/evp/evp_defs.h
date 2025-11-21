#ifndef EVP_DEFS_H
#define EVP_DEFS_H

#include "../../config/libs.h"

#ifdef __cplusplus
extern "C" {
#endif

// ==========================
// EVP_MD: algorithm descriptor
// ==========================
typedef struct _EVP_MD {
    const char *name;        // e.g., "SHA1", "SHA3-512", "RawSHAKE256"
    size_t digest_size;      // output size in bytes
    size_t block_size;       // internal block size
    size_t ctx_size;         // size of low-level context
    size_t default_out_len;  // for SHAKE / XOF functions

    void *ctx;               // pointer to low-level context

    bool (*hash_init_fn)(void *ctx);
    bool (*hash_update_fn)(void *ctx, const uint8_t *data, size_t len);
    bool (*hash_final_fn)(void *ctx, uint8_t *digest, size_t digest_size);
    bool (*hash_squeeze_fn)(void *ctx, uint8_t *output, size_t outlen);
} EVP_MD;

// ==========================
// EVP_HASH_CTX: runtime context
// ==========================
typedef struct _EVP_HASH_CTX {
    const struct _EVP_MD *md; // selected algorithm
    void *digest_ctx;         // pointer to low-level context
    size_t out_len;           // optional output length for XOFs
} EVP_HASH_CTX;

#ifdef __cplusplus
}
#endif

#endif // EVP_DEFS_H