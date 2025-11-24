#ifndef EVP_HASH_H
#define EVP_HASH_H

#include "../../utils/utils.h"
#include "../../utils/mem_utils.h"
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

// ==========================
// Initialization / Cleanup
// ==========================
TC_API TCLIB_STATUS EVP_HashInit(EVP_HASH_CTX *ctx, const EVP_MD *md);
TC_API EVP_HASH_CTX* EVP_HashInitAlloc(const EVP_MD *md, TCLIB_STATUS *status);

TC_API TCLIB_STATUS EVP_CShakeInit(EVP_HASH_CTX *ctx, const EVP_MD *md,
                                 const uint8_t *N, size_t N_len,
                                 const uint8_t *S, size_t S_len);

TC_API EVP_HASH_CTX* EVP_CShakeInitAlloc(const EVP_MD *md,
                                        const uint8_t *N, size_t N_len,
                                        const uint8_t *S, size_t S_len,
                                        TCLIB_STATUS *status);

TC_API TCLIB_STATUS EVP_HashUpdate(EVP_HASH_CTX *ctx, const uint8_t *data, size_t data_len);

/**
 * For FIXED OUTPUT hashes (MD5, SHA1, SHA2, SHA3-256, SHA3-512):
 *     - out_len is ignored; digest size is md->digest_size
 *
 * For XOF hashes (SHAKE128, SHAKE256):
 *     - out_len REQUIRED, user controls length
 */
TC_API TCLIB_STATUS EVP_HashFinal(EVP_HASH_CTX *ctx, uint8_t *digest, size_t digest_len);

TC_API TCLIB_STATUS EVP_HashFree(EVP_HASH_CTX *ctx);
TC_API TCLIB_STATUS EVP_HashReset(EVP_HASH_CTX *ctx);

// ==========================
// One-shot convenience
// ==========================
TC_API TCLIB_STATUS EVP_ComputeHash(
    const EVP_MD *md,
    uint8_t *digest,
    const uint8_t *data,
    size_t data_len,
    size_t out_len   // ignored for fixed-output MD; required for XOF
);

// ==========================
// One-shot cSHAKE convenience
// ==========================
TC_API TCLIB_STATUS EVP_ComputeCShake(
    const EVP_MD *md,
    uint8_t *digest,
    const uint8_t *data,
    size_t data_len,
    size_t out_len,
    const uint8_t *N, size_t N_len,
    const uint8_t *S, size_t S_len
);

// ==========================
// Hash comparison
// ==========================
// Note: Performs a constant time comparison to resist timing attacks.
TC_API int EVP_HashCompare(const uint8_t *a, const uint8_t *b, size_t len);

// ==========================
// Utility functions
// ==========================
TC_API void* EVP_HashCloneCtx(const void *ctx, const EVP_MD *md, TCLIB_STATUS *status);
TC_API size_t EVP_HashDigestSize(const EVP_HASH_CTX *ctx);  // for fixed-output hashes
TC_API size_t EVP_HashBlockSize(const EVP_HASH_CTX *ctx);
TC_API const char* EVP_HashName(const EVP_MD *md);

// ==========================
// Algorithm selection
// ==========================
TC_API const EVP_MD *EVP_MDByFlag(uint32_t algo_flag);

#ifdef __cplusplus
}
#endif

#endif // EVP_HASH_H