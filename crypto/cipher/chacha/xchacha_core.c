/*
 * CryptoForge - xchacha_core.c / XChaCha Core Implementation
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against WyChaProof test vectors. No hardware optimizations. Use with caution.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#include "../../../include/crypto/xchacha_core.h"

// ChaCha quarter-round function
#define QUARTER_ROUND(a, b, c, d) {      \
    a += b;  d ^= a;  d = ROTL32(d, 16);  \
    c += d;  b ^= c;  b = ROTL32(b, 12);  \
    a += b;  d ^= a;  d = ROTL32(d, 8);   \
    c += d;  b ^= c;  b = ROTL32(b, 7);   \
}

#define CHACHA_CONSTANT_0 0x61707865  // "expa"
#define CHACHA_CONSTANT_1 0x3320646e  // "nd 3"
#define CHACHA_CONSTANT_2 0x79622d32  // "2-by"
#define CHACHA_CONSTANT_3 0x6b206574  // "te k"

static FORCE_INLINE void ll_HChaCha_Permute(uint32_t state[16], int rounds) {
    for (int i = 0; i < rounds; i += 2) {
        // Column rounds
        QUARTER_ROUND(state[0], state[4], state[8], state[12]);
        QUARTER_ROUND(state[1], state[5], state[9], state[13]);
        QUARTER_ROUND(state[2], state[6], state[10], state[14]);
        QUARTER_ROUND(state[3], state[7], state[11], state[15]);
        // Diagonal rounds
        QUARTER_ROUND(state[0], state[5], state[10], state[15]);
        QUARTER_ROUND(state[1], state[6], state[11], state[12]);
        QUARTER_ROUND(state[2], state[7], state[8], state[13]);
        QUARTER_ROUND(state[3], state[4], state[9], state[14]);
    }
}

bool ll_HChaCha_DeriveSubkey(
             const uint8_t key[XCHACHA_KEY_SIZE],
             const uint8_t iv[16], uint8_t out[32],
             int rounds) {
    if (!key || !iv)
        return false;

    // Validate number of rounds (ChaCha supports 8, 12, or 20 rounds)
    if (rounds != CHACHA_ROUNDS_8 && rounds != CHACHA_ROUNDS_12 && rounds != CHACHA_ROUNDS_20)
        return false;

    uint32_t state[16];

    // The first four words of the state are constants (sigma)
    state[0] = CHACHA_CONSTANT_0;
    state[1] = CHACHA_CONSTANT_1;
    state[2] = CHACHA_CONSTANT_2;
    state[3] = CHACHA_CONSTANT_3;

    // Key words: input words 4-11 are derived from the key
    // For 256-bit key: use all 32 bytes directly
    state[4]  = LOAD32LE(key);
    state[5]  = LOAD32LE(key + 4);
    state[6]  = LOAD32LE(key + 8);
    state[7]  = LOAD32LE(key + 12);
    state[8]  = LOAD32LE(key + 16);
    state[9]  = LOAD32LE(key + 20);
    state[10] = LOAD32LE(key + 24);
    state[11] = LOAD32LE(key + 28);

    // state[12..15] = 16-byte HChaCha nonce (first 16 bytes of XChaCha nonce)
    state[12] = LOAD32LE(iv);
    state[13] = LOAD32LE(iv + 4);
    state[14] = LOAD32LE(iv + 8);
    state[15] = LOAD32LE(iv + 12);

    // Apply the ChaCha permutation (no feed-forward) for HChaCha subkey derivation
    ll_HChaCha_Permute(state, rounds);

    // Extract first and last rows as 256-bit subkey
    for (int i = 0; i < 4; i++)
        STORE32LE(out + i * 4, state[i]);            // first row
    for (int i = 0; i < 4; i++)
        STORE32LE(out + (i + 4) * 4, state[12 + i]); // last row

    return true;
}
