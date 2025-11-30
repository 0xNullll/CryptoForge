#ifndef EVP_HASH_H
#define EVP_HASH_H

#include "../../utils/misc_utils.h"
#include "../../utils/mem.h"
#include "../../utils/tclib_status.h"

#include "../../config/crypto_config.h"
#include "../../config/libs.h"

#include "evp_defs.h"
#include "evp_flags.h"

#include "../hash/md/md5.h"
#include "../hash/sha/sha1.h"
#include "../hash/sha/sha256.h"
#include "../hash/sha/sha512.h"

#include "../hash/sha/keccak/keccak.h"
#include "../hash/sha/keccak/sha3.h"
#include "../hash/sha/keccak/shake.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _EVP_XOF_OPTS {
    // Output length
    size_t out_len;     // requested output length

    // Fixed-size customization strings
    uint8_t N[EVP_MAX_CUSTOMIZATION];
    size_t N_len;
    uint8_t S[EVP_MAX_CUSTOMIZATION];
    size_t S_len;

    // Bookkeeping
    int finalized;
    int custom_absorbed;
    int emptyNameCustom;

    int isHeapAlloc;          // 1 if allocated by library (heap), 0 if user stack
} EVP_XOF_OPTS;

typedef struct _EVP_HASH_CTX {
    const struct _EVP_MD *md;  // selected algorithm
    const void *opts;
    void *digest_ctx;          // pointer to low-level context
    size_t out_len;            // optional output length for XOFs

    int isFinalized;
    int isHeapAlloc;           // 1 if allocated by library (heap), 0 if user stack
    int isHeapAllocOpts;
} EVP_HASH_CTX;

typedef struct _EVP_MDEntry {
    uint32_t flag;
    const EVP_MD *(*EVP_MDGetter)(void);
} EVP_MDEntry;

// ==========================
// Algorithm selection
// ==========================
TCLIB_API const EVP_MD *EVP_MDByFlag(uint32_t algo_flag);

// ==========================
// Hash initialization / cleanup
// ==========================
TCLIB_API TCLIB_STATUS EVP_HashInit(EVP_HASH_CTX *ctx, const EVP_MD *md, const EVP_XOF_OPTS *opts);
TCLIB_API EVP_HASH_CTX* EVP_HashInitAlloc(const EVP_MD *md, const EVP_XOF_OPTS *opts, TCLIB_STATUS *status);

TCLIB_API TCLIB_STATUS EVP_HashUpdate(EVP_HASH_CTX *ctx, const uint8_t *data, size_t data_len);
TCLIB_API TCLIB_STATUS EVP_HashFinal(EVP_HASH_CTX *ctx, uint8_t *digest, size_t digest_len);

// Frees internal buffers of a pre-allocated EVP_HASH_CTX
TCLIB_API TCLIB_STATUS EVP_HashFree(EVP_HASH_CTX *ctx);

// Frees internal buffers + heap-allocated EVP_HASH_CTX
TCLIB_API TCLIB_STATUS EVP_HashFreeAlloc(EVP_HASH_CTX **p_ctx);

// ==========================
// One-shot hash convenience
// ==========================
TCLIB_API TCLIB_STATUS EVP_ComputeHashFixed(
    const EVP_MD  *md,
    uint8_t       *digest,
    const uint8_t *data,
    size_t         data_len
);

TCLIB_API TCLIB_STATUS EVP_ComputeHashXof(
    const EVP_MD       *md,
    uint8_t            *digest,
    const uint8_t      *data,
    size_t              data_len,
    size_t              out_len,
    const EVP_XOF_OPTS *opts     // Optional: hash-specific options
);

// ==========================
// Hash comparison
// ==========================
// Performs constant-time comparison to resist timing attacks
TCLIB_API int EVP_HashCompare(const uint8_t *a, const uint8_t *b, size_t len);

// ==========================
// Hash utility functions
// ==========================
TCLIB_API TCLIB_STATUS EVP_HashCloneCtx(EVP_HASH_CTX *dst, const EVP_HASH_CTX *src);
TCLIB_API EVP_HASH_CTX *EVP_HashCloneCtxAlloc(const EVP_HASH_CTX *src, TCLIB_STATUS *status);

TCLIB_API size_t EVP_HashDigestSize(const EVP_HASH_CTX *ctx);  // fixed-output hashes
TCLIB_API size_t EVP_HashBlockSize(const EVP_HASH_CTX *ctx);
TCLIB_API const char* EVP_HashName(const EVP_MD *md);

// ==========================
// XOF options initialization / cleanup
// ==========================
TCLIB_API TCLIB_STATUS EVP_XOFOptsInit(
    EVP_XOF_OPTS *opts,
    const uint8_t *N, size_t N_len,
    const uint8_t *S, size_t S_len,
    size_t out_len
);

TCLIB_API EVP_XOF_OPTS* EVP_XOFOptsInitAlloc(
    const uint8_t *N, size_t N_len,
    const uint8_t *S, size_t S_len,
    size_t out_len,
    TCLIB_STATUS *status
);

TCLIB_API void EVP_XOFOptsFree(EVP_XOF_OPTS *opts);
TCLIB_API void EVP_XOFOptsFreeAlloc(EVP_XOF_OPTS **p_opts);

TCLIB_API TCLIB_STATUS EVP_CloneXOFOpts(EVP_XOF_OPTS *dst, const EVP_XOF_OPTS *src);
TCLIB_API EVP_XOF_OPTS *EVP_CloneXOFOptsAlloc(const EVP_XOF_OPTS *src, TCLIB_STATUS *status);

#ifdef __cplusplus
}
#endif

#endif // EVP_HASH_H