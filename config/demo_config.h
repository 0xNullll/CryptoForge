#ifndef DEMO_HASH_H
#define DEMO_HASH_H

#include "crypto_config.h"  // include high-level flags

#if ENABLE_TESTS  // only include/demo code if tests are enabled

#include "../crypto/hash/md/md5.h"
#include "../crypto/hash/sha/sha1.h"
#include "../crypto/hash/sha/sha256.h"
#include "../crypto/hash/sha/sha512.h"
#include "../crypto/hash/sha/keccak/sha3.h"
#include "../crypto/hash/sha/keccak/shake.h"

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

TC_API void DEMO_md(const uint8_t *data, size_t len);

TC_API void DEMO_sha(const uint8_t *data, size_t len);

TC_API void DEMO_sha3(const uint8_t *data, size_t len);

// Test helper (for dev)
TC_API void DEMO_EVP_test_MD(
    const EVP_MD *md,
    const uint8_t *data,
    size_t len,
    size_t out_len
);

#ifdef __cplusplus
}
#endif

#endif // ENABLE_TESTS

#endif // DEMO_HASH_H
