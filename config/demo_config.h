#ifndef DEMO_HASH_H
#define DEMO_HASH_H

#include "crypto_config.h"  // include high-level flags
#include "../utils/cf_status.h"
#include "../utils/misc_utils.h"

#if ENABLE_TESTS  // only include/demo code if tests are enabled

#include "../crypto/hash/sha/keccak/shake.h"
#include "../crypto/mac/hmac.h"
#include "../crypto/mac/kmac.h"
#include "../crypto/kdf/hkdf.h"
#include "../crypto/evp/evp_defs.h"
#include "../crypto/evp/evp_flags.h"
#include "../crypto/evp/evp_hash.h"


#ifdef __cplusplus
extern "C" {
#endif

// typedef struct {
//     const uint8_t *data;
//     size_t data_len;
//     const uint8_t *S;
//     size_t S_len;
//     const uint8_t *outval;
//     size_t outsz;
// } CSHAKE_TEST_VECTOR;

// Utility to print a digest in hex
FORCE_INLINE void DEMO_print_hex(const uint8_t *digest, size_t size) {
    for (size_t i = 0; i < size; i++)
        printf("%02x", digest[i]);
    printf("\n");
}

// Test helper (for dev)
CF_API void test_all_hashes(const uint8_t *input, size_t input_len, const EVP_XOF_OPTS *opts);

CF_API void test_all_hashes_high(const uint8_t *input, size_t input_len, const EVP_XOF_OPTS *opts);

CF_API void test_all_hmacs(const uint8_t *key, size_t key_len, const uint8_t *input, size_t input_len);

CF_API void test_all_kmacs(
    const uint8_t *key, size_t key_len,
    const uint8_t *input, size_t input_len,
    const uint8_t *S, size_t S_len);

#ifdef __cplusplus
}
#endif

#endif // ENABLE_TESTS

#endif // DEMO_HASH_H
