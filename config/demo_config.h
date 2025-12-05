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
#include "../crypto/enc/base16.h"
#include "../crypto/enc/base32.h"
#include "../crypto/enc/base64.h"
#include "../crypto/enc/base58.h"

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

CF_API void test_all_hkdfs(
    const uint8_t *info, size_t info_len,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *ikm, size_t ikm_len,
    size_t okm_len);

CF_API void test_base16(const char *label, const uint8_t *input, size_t len, uint32_t mode);
CF_API void test_hex_base16(const char *label, const uint8_t *input, size_t len, uint32_t mode);

CF_API void test_base32(const char *label, const uint8_t *input, size_t len, int noPad);
CF_API void test_hex_base32(const char *label, const uint8_t *input, size_t len, int noPad);

CF_API void test_base58(const char *label, const uint8_t *input, size_t len);
CF_API void test_hex_base58(const char *label, const uint8_t *input, size_t len);

CF_API void test_base64(const char *label, const uint8_t *input, size_t len, uint32_t enc_mode, uint32_t dec_mode);
CF_API void test_hex_base64(const char *label, const uint8_t *input, size_t len, uint32_t enc_mode, uint32_t dec_mode);

#ifdef __cplusplus
}
#endif

#endif // ENABLE_TESTS

#endif // DEMO_HASH_H
