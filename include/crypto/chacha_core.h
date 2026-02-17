/*
 * CryptoForge - chacha_core.h / ChaCha Core Interface
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against WyChaProof test vectors. No hardware optimizations. Use with caution.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#ifndef CHACHA_CORE_H
#define CHACHA_CORE_H

#include "../config/libs.h"

#include "../utils/mem.h"
#include "../utils/misc.h"
#include "../utils/bitops.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CHACHA_ROUNDS_8      8
#define CHACHA_ROUNDS_12     12
#define CHACHA_ROUNDS_20     20

#define CHACHA_BLOCK_SIZE 64       // 512-bit block
#define CHACHA_KEY_SIZE_128   16   // 128-bit key (optional, smaller variant)
#define CHACHA_KEY_SIZE_256   32   // 256-bit key (default)
#define CHACHA_IV_SIZE 12          // 96-bit iv

// Low-level ChaCha state
typedef struct {
    uint32_t state[16];                    // internal 16-word state
    uint8_t  keystream[CHACHA_BLOCK_SIZE]; // buffer for generated block
    size_t   pos;                          // current position in keystream buffer
    int      rounds;                       // number of ChaCha rounds (can be 8, 12 or 20)
} ll_CHACHA_CTX;

// Initialize ChaCha context with key, iv, counter, and custom rounds
bool ll_CHACHA_Init(ll_CHACHA_CTX *ctx, const uint8_t *key, size_t key_len, 
                    const uint8_t iv[CHACHA_IV_SIZE], uint32_t counter,
                    int rounds);

bool ll_CHACHA_ProcessBlock(ll_CHACHA_CTX *ctx);

// Generate keystream and XOR with input
bool ll_CHACHA_Cipher(ll_CHACHA_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif // CHACHA_CORE_H