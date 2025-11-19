#ifndef DEMO_HASH_H
#define DEMO_HASH_H

#include "sha1.h"
#include "sha2.h"
#include "sha3.h"
#include "shake.h"

#ifdef __cplusplus
extern "C" {
#endif

void print_hex(const uint8_t *digest, size_t size);
void compute_and_print_hashes(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif // DEMO_HASH_H
