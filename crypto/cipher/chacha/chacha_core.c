/*
 * CryptoForge - chacha_core.c / ChaCha Core Implementation
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "../../../include/crypto/chacha_core.h"

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

bool ll_CHACHA_Init(ll_CHACHA_CTX *ctx, const uint8_t *key, size_t key_len, 
                    const uint8_t iv[CHACHA_IV_SIZE], uint32_t counter,
                    int rounds) {
    if (!ctx || !key || !iv)
        return false;

    // Accept only supported key sizes: 128-bit or 256-bit
    if (key_len != CHACHA_KEY_SIZE_128 && key_len != CHACHA_KEY_SIZE_256)
        return false;

    // Validate number of rounds (ChaCha supports 8, 12, or 20 rounds)
    if (rounds != CHACHA_ROUNDS_8 && rounds != CHACHA_ROUNDS_12 && rounds != CHACHA_ROUNDS_20)
        return false;

    // Save the number of rounds to be applied in this context
    ctx->rounds = rounds;

    uint32_t *w = ctx->state;

    // The first four words of the state are constants (sigma)
    w[0] = CHACHA_CONSTANT_0;
    w[1] = CHACHA_CONSTANT_1;
    w[2] = CHACHA_CONSTANT_2;
    w[3] = CHACHA_CONSTANT_3;

    // Key words: input words 4-11 are derived from the key
    // For 256-bit key: use all 32 bytes directly
    // For 128-bit key: repeat the first 16 bytes to fill 8 words
    w[4]  = LOAD32LE(key);
    w[5]  = LOAD32LE(key + 4);
    w[6]  = LOAD32LE(key + 8);
    w[7]  = LOAD32LE(key + 12);

    if (key_len == CHACHA_KEY_SIZE_256) {
        w[8]  = LOAD32LE(key + 16);
        w[9]  = LOAD32LE(key + 20);
        w[10] = LOAD32LE(key + 24);
        w[11] = LOAD32LE(key + 28);
    } else { // 128-bit key
        // Repeat first 16 bytes to fill second half of key schedule
        w[8]  = LOAD32LE(key);
        w[9]  = LOAD32LE(key + 4);
        w[10] = LOAD32LE(key + 8);
        w[11] = LOAD32LE(key + 12);    
    }

    // Input word 12 is the block counter (usually starts at 0)
    w[12] = counter;

    // Input words 13-15 are the 96-bit iv
    w[13] = LOAD32LE(iv);
    w[14] = LOAD32LE(iv + 4);
    w[15] = LOAD32LE(iv + 8);

    // Initialize keystream position to zero
    ctx->pos = 0;

    return true;
}

bool ll_CHACHA_ProcessBlock(ll_CHACHA_CTX *ctx) {
    uint32_t w[16];
    int i;

    //Copy the current state into a working array
    for (i = 0; i < 16; i++) {
        w[i] = ctx->state[i];
    }

    //Perform the ChaCha rounds in pairs (double-rounds)
    for (i = 0; i < ctx->rounds; i += 2) {
        //Column rounds
        QUARTER_ROUND(w[0], w[4], w[8], w[12]);
        QUARTER_ROUND(w[1], w[5], w[9], w[13]);
        QUARTER_ROUND(w[2], w[6], w[10], w[14]);
        QUARTER_ROUND(w[3], w[7], w[11], w[15]);

        //Diagonal rounds
        QUARTER_ROUND(w[0], w[5], w[10], w[15]);
        QUARTER_ROUND(w[1], w[6], w[11], w[12]);
        QUARTER_ROUND(w[2], w[7], w[8], w[13]);
        QUARTER_ROUND(w[3], w[4], w[9], w[14]);
    }

    //Add the original state to the result (feedforward)
    for (i = 0; i < 16; i++) {
        w[i] += ctx->state[i];
    }

    //Serialize the words into the keystream buffer
    for (i = 0; i < 16; i++) {
        STORE32LE(ctx->keystream + i * 4, w[i]);
    }

    return true;
}

bool ll_CHACHA_Cipher(ll_CHACHA_CTX *ctx,
                      const uint8_t *in, size_t in_len,
                      uint8_t *out) {
    if (!ctx || !in || !out)
        return false;

    size_t i = 0; // input/output index

    while (i < in_len) {
        // Generate a new keystream block if needed
        if (ctx->pos == 0 || ctx->pos == CHACHA_BLOCK_SIZE) {
            ll_CHACHA_ProcessBlock(ctx);

            // Increment block counter
            ctx->state[12]++;
            if (ctx->state[12] == 0)
                ctx->state[13]++;

            ctx->pos = 0;
            }

        // How many bytes we can consume from the current keystream
        size_t remaining_keystream = CHACHA_BLOCK_SIZE - ctx->pos;
        size_t remaining_input = in_len - i;
        size_t chunk = remaining_keystream < remaining_input ? remaining_keystream : remaining_input;

        // XOR the chunk
        for (size_t j = 0; j < chunk; j++)
            out[i + j] = in[i + j] ^ ctx->keystream[ctx->pos + j];

        // Advance counters
        ctx->pos += chunk;
        i += chunk;
    }

    return true;
}
