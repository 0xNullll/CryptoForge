#ifndef EVP_DEFS_H
#define EVP_DEFS_H

#include "../../config/libs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EVP_MAX_KEY_SIZE 512        // bytes
#define EVP_MAX_CUSTOMIZATION 512   // bytes

// ==========================
// EVP_MD: algorithm descriptor
// ==========================
typedef struct _EVP_MD {
    uint32_t id;             // EVP hash ID/flag
    uint8_t domain;          // Optional Keccak domain/prefix for cSHAKE
    size_t digest_size;      // output size in bytes
    size_t block_size;       // internal block size
    size_t ctx_size;         // size of low-level context
    size_t default_out_len;  // for SHAKE / XOF functions

    bool (*hash_init_fn)(void *ctx, const void *opts);
    bool (*hash_update_fn)(void *ctx, const uint8_t *data, size_t len);
    bool (*hash_final_fn)(void *ctx, uint8_t *digest, size_t digest_size);
    bool (*hash_squeeze_fn)(void *ctx, uint8_t *output, size_t outlen);
} EVP_MD;

typedef struct _EVP_XOF_OPTS EVP_XOF_OPTS;

typedef struct _EVP_MDEntry EVP_MDEntry;

typedef struct _EVP_HASH_CTX EVP_HASH_CTX;

#ifdef __cplusplus
}
#endif

#endif // EVP_DEFS_H