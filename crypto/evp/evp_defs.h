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

typedef struct _EVP_XOF_CSHAKE_OPTS{
    const uint8_t *N;      // function name for cSHAKE
    size_t N_len;
    const uint8_t *S;      // customization string
    size_t S_len;
    size_t out_len;        // requested output length
} EVP_XOF_CSHAKE_OPTS;

typedef struct _EVP_MDEntry{
    uint32_t flag;
    const EVP_MD *(*EVP_MDGetter)(void);
} EVP_MDEntry;

// ==========================
// EVP_HASH_CTX: runtime context
// ==========================
typedef struct _EVP_HASH_CTX {
    const struct _EVP_MD *md; // selected algorithm
    const void *opts;
    void *digest_ctx;         // pointer to low-level context
    size_t out_len;           // optional output length for XOFs

    int isFinalized;
    int isHeapAlloc;          // 1 if allocated by library (heap), 0 if user stack
} EVP_HASH_CTX;

// ==========================
// HMAC_CTX: runtime context
// ==========================
typedef struct _EVP_HMAC_CTX {
    const EVP_MD *md;           // Underlying hash algorithm
    EVP_HASH_CTX *inner_ctx;    // Inner hash context
    EVP_HASH_CTX *outer_ctx;    // Outer hash context

    uint8_t key_block[128];     // Padded key block (max 128 for SHA-512)
    size_t key_len;             // Original key length

    size_t out_len;             // Output length (for XOFs)
    bool is_xof;                // True if underlying hash is XOF (SHAKE)

} EVP_HMAC_CTX;


#ifdef __cplusplus
}
#endif

#endif // EVP_DEFS_H