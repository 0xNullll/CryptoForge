#ifndef DEMO_HASH_H
#define DEMO_HASH_H

#include "crypto_config.h"  // include high-level flags
#include "../utils/tclib_status.h"

#if ENABLE_TESTS  // only include/demo code if tests are enabled

#include "../crypto/mac/hmac.h"

#include "../crypto/evp/evp_defs.h"
#include "../crypto/evp/evp_flags.h"
#include "../crypto/evp/evp_hash.h"


#ifdef __cplusplus
extern "C" {
#endif

// Utility to print a digest in hex
FORCE_INLINE void DEMO_print_hex(const uint8_t *digest, size_t size) {
    for (size_t i = 0; i < size; i++)
        printf("%02x", digest[i]);
    printf("\n");
}

// Test helper (for dev)
TC_API void DEMO_EVP_test_MD(
    const EVP_MD *md,
    const uint8_t *data,
    size_t len,
    size_t out_len
);

void test_all_hmacs(const uint8_t *key, size_t key_len, const uint8_t *input, size_t input_len);

#ifdef __cplusplus
}
#endif

#endif // ENABLE_TESTS

#endif // DEMO_HASH_H
