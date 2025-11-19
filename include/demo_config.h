#ifndef DOMO_CONFIG_H
#define DOMO_CONFIG_H

#include "libs.h"
#include "crypto_config.h"
#include "sha1.h"
#include "sha2.h"
#include "sha3.h"
#include "shake.h"

#ifdef __cplusplus
extern "C" {
#endif

void print_hex(const uint8_t *digest, size_t size) {
    for (size_t i = 0; i < size; i++)
        printf("%02x", digest[i]);
    printf("\n");
}

void compute_and_print_hashes(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif // DOMO_CONFIG_H