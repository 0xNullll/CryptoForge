#ifndef DEMO_HASH_H
#define DEMO_HASH_H

#include "crypto_config.h"  // include high-level flags

#if ENABLE_TESTS  // only include/demo code if tests are enabled

#include "../crypto/hash/sha/sha1.h"
#include "../crypto/hash/sha/sha256.h"
#include "../crypto/hash/sha/sha512.h"
#include "../crypto/hash/sha/keccak/sha3.h"
#include "../crypto/hash/sha/keccak/shake.h"

#ifdef __cplusplus
extern "C" {
#endif

// Utility to print a digest in hex
FORCE_INLINE void print_hex(const uint8_t *digest, size_t size) {
    for (size_t i = 0; i < size; i++)
        printf("%02x", digest[i]);
    printf("\n");
}

#if ENABLE_SHA || ENABLE_SHA3

// Compute all enabled hashes and print results
void compute_and_print_hashes(const uint8_t *data, size_t len);

#endif // ENABLE_SHA || ENABLE_SHA3

#ifdef __cplusplus
}
#endif

#endif // ENABLE_TESTS

#endif // DEMO_HASH_H
