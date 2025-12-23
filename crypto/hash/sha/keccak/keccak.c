/*
 * CryptoForge - keccak.c / keccak Core Implementation
 * Copyright (C) 2025 0xNullll
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the MIT License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * You should have received a copy of the MIT License along with this program.
 * If not, see <https://opensource.org/licenses/MIT>.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#include "keccak.h"

// Precomputed rotation offsets for the ρ (rho) step of Keccak-f[1600].
// Each entry rhotates[x][y] specifies the number of bits to rotate the lane A[x][y] left.
// Derived from Section 3.2.2 of FIPS PUB 202, modulo lane size w=64.
static const uint8_t rhotates[5][5] = {
    {  0,  1, 62, 28, 27 },
    { 36, 44,  6, 55, 20 },
    {  3, 10, 43, 25, 39 },
    { 41, 45, 15, 21,  8 },
    { 18,  2, 61, 56, 14 }
};

// Precomputed round constants for the ι (iota) step of Keccak-f[1600].
// Each entry iotas[round] corresponds to the round constant RC for that round. 
// Derived from Section 3.2.5 of FIPS PUB 202, expressed as 64-bit unsigned integers.
// Precomputing the values improves clarity and runtime efficiency.
static const uint64_t iotas[24] = {
    U64(0x0000000000000001), U64(0x0000000000008082),
    U64(0x800000000000808a), U64(0x8000000080008000),
    U64(0x000000000000808b), U64(0x0000000080000001),
    U64(0x8000000080008081), U64(0x8000000000008009),
    U64(0x000000000000008a), U64(0x0000000000000088),
    U64(0x0000000080008009), U64(0x000000008000000a),
    U64(0x000000008000808b), U64(0x800000000000008b),
    U64(0x8000000000008089), U64(0x8000000000008003),
    U64(0x8000000000008002), U64(0x8000000000000080),
    U64(0x000000000000800a), U64(0x800000008000000a),
    U64(0x8000000080008081), U64(0x8000000000008080),
    U64(0x0000000080000001), U64(0x8000000080008008)
};

/*
 * Straightforward implementation of the θ (theta) step of Keccak-f[1600],
 * following Section 3.2.1 of FIPS PUB 202 "SHA-3 Standard: Permutation-Based
 * Hash and Extendible-Output Functions" as closely as possible. 
 */
static void Theta(uint64_t A[5][5]) {
    uint64_t C[5], D[5];

    C[0] = A[0][0];
    C[1] = A[0][1];
    C[2] = A[0][2];
    C[3] = A[0][3];
    C[4] = A[0][4];

    for (int y = 1; y < 5; y++) {
        C[0] ^= A[y][0];
        C[1] ^= A[y][1];
        C[2] ^= A[y][2];
        C[3] ^= A[y][3];
        C[4] ^= A[y][4];
    }

    D[0] = ROTL64(C[1], 1) ^ C[4];
    D[1] = ROTL64(C[2], 1) ^ C[0];
    D[2] = ROTL64(C[3], 1) ^ C[1];
    D[3] = ROTL64(C[4], 1) ^ C[2];
    D[4] = ROTL64(C[0], 1) ^ C[3];

    for (int y = 0; y < 5; y++) {
        A[y][0] ^= D[0];
        A[y][1] ^= D[1];
        A[y][2] ^= D[2];
        A[y][3] ^= D[3];
        A[y][4] ^= D[4];
    }
}

// /*
//  * Straightforward, table-driven implementation of the ρ (rho) step of Keccak-f[1600],
//  * following Section 3.2.2 of FIPS PUB 202 "SHA-3 Standard: Permutation-Based
//  * Hash and Extendible-Output Functions". 
//  * 
//  * Uses precomputed lane rotation offsets (rhotates) for maximum clarity and efficiency.
// 

static void Rho(uint64_t A[5][5]) {
    for (int y = 0; y < 5; y++) {
        A[y][0] = ROTL64(A[y][0], rhotates[y][0]);
        A[y][1] = ROTL64(A[y][1], rhotates[y][1]);
        A[y][2] = ROTL64(A[y][2], rhotates[y][2]);
        A[y][3] = ROTL64(A[y][3], rhotates[y][3]);
        A[y][4] = ROTL64(A[y][4], rhotates[y][4]);
    }
}

/*
 * Straightforward, fully unrolled implementation of the π (pi) step of Keccak-f[1600],
 * following Section 3.2.3 of FIPS PUB 202 "SHA-3 Standard: Permutation-Based
 * Hash and Extendible-Output Functions".
 *
 * Maps each lane A[x][y] to its new position A[y][(2x + 3y) % 5] according to the spec.
 * Loop is unrolled manually to avoid modulo operations and improve performance.
 */
static void Pi(uint64_t A[5][5]) {
    uint64_t T[5][5];

    // T = A
    SECURE_MEMCPY(T, A, sizeof(T));

    // A[y][x] = T[x][(3*y+x)%5]
    A[0][0] = T[0][0];
    A[0][1] = T[1][1];
    A[0][2] = T[2][2];
    A[0][3] = T[3][3];
    A[0][4] = T[4][4];

    A[1][0] = T[0][3];
    A[1][1] = T[1][4];
    A[1][2] = T[2][0];
    A[1][3] = T[3][1];
    A[1][4] = T[4][2];

    A[2][0] = T[0][1];
    A[2][1] = T[1][2];
    A[2][2] = T[2][3];
    A[2][3] = T[3][4];
    A[2][4] = T[4][0];

    A[3][0] = T[0][4];
    A[3][1] = T[1][0];
    A[3][2] = T[2][1];
    A[3][3] = T[3][2];
    A[3][4] = T[4][3];

    A[4][0] = T[0][2];
    A[4][1] = T[1][3];
    A[4][2] = T[2][4];
    A[4][3] = T[3][0];
    A[4][4] = T[4][1];
}

/*
 * Straightforward, row-wise implementation of the χ (chi) step of Keccak-f[1600],
 * following Section 3.2.4 of FIPS PUB 202 "SHA-3 Standard: Permutation-Based
 * Hash and Extendible-Output Functions".
 *
 * Applies a non-linear transformation on each row: 
 * each bit A[y][x] is XORed with the AND of the complement of the next bit and the bit after that.
 * Loop over rows; each row is processed with fully unrolled bitwise operations for clarity.
 */
static void Chi(uint64_t A[5][5]) {
    uint64_t C[5];

    for (int y = 0; y < 5; y++) {
        C[0] = A[y][0] ^ (~A[y][1] & A[y][2]);
        C[1] = A[y][1] ^ (~A[y][2] & A[y][3]);
        C[2] = A[y][2] ^ (~A[y][3] & A[y][4]);
        C[3] = A[y][3] ^ (~A[y][4] & A[y][0]);
        C[4] = A[y][4] ^ (~A[y][0] & A[y][1]);

        A[y][0] = C[0];
        A[y][1] = C[1];
        A[y][2] = C[2];
        A[y][3] = C[3];
        A[y][4] = C[4];
    }
}

/*
 * Straightforward implementation of the ι (iota) step of Keccak-f[1600],
 * following Section 3.2.5 of FIPS PUB 202 "SHA-3 Standard: Permutation-Based
 * Hash and Extendible-Output Functions".
 *
 * Injects the round constant for round 'i' into the first lane A[0][0] via XOR.
 * Precomputed 64-bit constants (iotas) are used for clarity and efficiency.
 */
static void Iota(uint64_t A[5][5], size_t i) {
    A[0][0] ^= iotas[i];
}

/*
 * Executes the Keccak-p[b, nr] permutation on state A,
 * performing 'nr' rounds as specified in FIPS PUB 202.
 *
 * Each round applies, in order, the five step mappings:
 * θ (Theta), ρ (Rho), π (Pi), χ (Chi), and ι (Iota).
 * The number of rounds is parameterized by 'nr', and precomputed
 * constants and rotation offsets are used for efficiency.
 */
static FORCE_INLINE void Round(uint64_t A[5][5], size_t i, uint64_t lane_mask) {
    Theta(A);
    Rho(A);
    Pi(A);
    Chi(A);

    // Apply lane mask after each step or at least here
    for (size_t y = 0; y < 5; y++) {
        for (size_t x = 0; x < 5; x++) {
            A[y][x] &= lane_mask;
        }
    }

    Iota(A, i);  // round constant step
}

// ======================
// Keccak block functions
// ======================
static FORCE_INLINE void absorb_block(uint64_t A[5][5], const uint8_t *buf, size_t r) {
    size_t lanes = r / 8;
    for (size_t i = 0; i < lanes; i++) {
        size_t x = i % 5;
        size_t y = i / 5;
        uint64_t lane = TWISTED_LOAD64(buf + i * 8);

    A[y][x] ^= lane;
    }
}

static FORCE_INLINE void squeeze_block(uint64_t A[5][5], uint8_t *buf, size_t r) {
    size_t lanes = r / 8;
    for (size_t i = 0; i < lanes; i++) {
        size_t x = i % 5;
        size_t y = i / 5;
        
        uint64_t lane = A[y][x];
        
        TWISTED_STORE64(buf + i * 8, lane);
    }
}

bool ll_keccak_p(uint64_t state[5][5], unsigned int w, unsigned int nr) {
    if (!state || nr > KECCAK_ROUNDS || (w != 64 && w != 32)) return false;

    uint64_t mask = (w == 64) ? 0xFFFFFFFFFFFFFFFFULL : 0xFFFFFFFFULL;

    for (unsigned int i = 0; i < nr; i++) {
        Round(state, i , mask); // pass mask to Round so lane size is applied
    }

    return true;
}

// =======================
// ll_KECCAK_CTX wrappers
// =======================
bool ll_keccak_sponge_init(ll_KECCAK_CTX *ctx, size_t rate, uint8_t suffix) {
    SECURE_MEMSET(ctx->state, 0, sizeof(ctx->state));
    SECURE_MEMSET(ctx->buf, 0, sizeof(ctx->buf));
    ctx->buf_len = 0;
    ctx->rate = rate;
    ctx->suffix = suffix;
    ctx->finalized = 0;
    return true;
}

// void print_keccak_state_twisted(const uint64_t state[5][5]) {
//     printf("Keccak state (twisted byte view):\n");

//     // Loop over lanes in "twisted" order (swap x and y for illustration)
//     for (int y = 0; y < 5; y++) {
//         for (int x = 0; x < 5; x++) {
//             uint64_t lane = state[x][y];
//             // Print lane byte-by-byte, LSB first
//             for (int b = 0; b < 8; b++) {
//                 uint8_t byte = (lane >> (8*b)) & 0xFF;
//                 printf("%02X ", byte);
//             }
//             printf("  "); // separate lanes
//         }
//         printf("\n");
//     }
//     printf("\n");
// }

// absorb into ctx (buffers partial blocks, processes full blocks)
bool ll_keccak_sponge_absorb(ll_KECCAK_CTX *ctx, const uint8_t *input, size_t inlen) {
    if (ctx->finalized) return false; // Cannot absorb after finalization

    size_t offset = 0;

    while (inlen > 0) {
        size_t space = ctx->rate - ctx->buf_len;
        size_t to_copy = (inlen < space) ? inlen : space;

        SECURE_MEMCPY(ctx->buf + ctx->buf_len, input + offset, to_copy);
        ctx->buf_len += to_copy;
        offset += to_copy;
        inlen -= to_copy;

        if (ctx->buf_len == ctx->rate) {
            absorb_block(ctx->state, ctx->buf, ctx->rate);
            ll_keccak_p(ctx->state, 64, KECCAK_ROUNDS);
            ctx->buf_len = 0;
        }
    }

    return true;
}

// finalization: multi-rate padding (domain suffix + 10*1), absorb last block
bool ll_keccak_sponge_final(ll_KECCAK_CTX *ctx) {
    if (ctx->finalized) return false;

    size_t r = ctx->rate;
    size_t num = ctx->buf_len;

    SECURE_MEMSET(ctx->buf + num, 0, r - num);

    if (num == r - 1)
        ctx->buf[num] ^= ctx->suffix ^ 0x80;  // combine suffix + final bit
    else {
        ctx->buf[num] ^= ctx->suffix;
        ctx->buf[r - 1] ^= 0x80;
    }

    absorb_block(ctx->state, ctx->buf, r);
    ll_keccak_p(ctx->state, 64, KECCAK_ROUNDS);

    ctx->buf_len = 0;
    ctx->finalized = 1;
    return true;
}

// squeeze: produce outlen bytes. Uses permutation between full-rate blocks
bool ll_keccak_sponge_squeeze(ll_KECCAK_CTX *ctx, uint8_t *output, size_t outlen) {
    if (!ctx->finalized) {
        if (!ll_keccak_sponge_final(ctx)) return false;
    }

    size_t offset = 0;
    uint8_t tmp[200];

    while (outlen > 0) {
        size_t block = (outlen < ctx->rate) ? outlen : ctx->rate;

        // always squeeze into tmp, copy requested bytes
        squeeze_block(ctx->state, tmp, ctx->rate);
        SECURE_MEMCPY(output + offset, tmp, block);

        offset += block;
        outlen -= block;

        if (outlen > 0)
            ll_keccak_p(ctx->state, 64, KECCAK_ROUNDS);
    }

    return true;
}
