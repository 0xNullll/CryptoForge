/*
 * CryptoForge - aes_core.c / AES Core Implementation
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

#include "../../../include/crypto/aes_core.h"

static const uint8_t sBox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t rsBox[256] = {
  	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static const uint8_t rCon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/*
 * Multiply a single byte by {02} in GF(2^8) (AES finite field)
 * Equivalent to the XTIME operation defined in the AES specification.
 */
static FORCE_INLINE uint8_t XtimeByte(uint8_t b) {
    // Create mask: 0x1b if high bit is set, 0x00 otherwise
    uint8_t mask = -(b >> 7);  // high bit: 1 -> 0xFF, 0 -> 0x00
    return (b << 1) ^ (0x1b & mask);
}

/*
 * Multiply two bytes in GF(2^8) using branchless mask
 * Performs bitwise multiplication modulo the AES irreducible polynomial.
 */
static uint8_t Mul(uint8_t x, uint8_t y) {
    uint8_t r = 0;

    for (int i = 0; i < 8; i++) {
        // Create mask: 0xFF if LSB of y is 1, 0x00 if 0
        uint8_t mask = -(y & 1);

        // Conditionally XOR x into r using mask
        r ^= x & mask;

        // Multiply x by 2 in GF(2^8) (Xtime)
        x = XtimeByte(x);

        // Shift y to process next bit
        y >>= 1;
    }

    return r;
}

/*
 * Rotate a 32-bit word left by 8 bits (one byte).
 * Used in AES key schedule during the RotWord step.
 */
static FORCE_INLINE uint32_t RotWord(uint32_t x) {
    return (x << 8) | (x >> 24);
}

/*
 * Apply the AES S-box substitution to each byte of a 32-bit word.
 * Used in the key expansion routine (SubWord operation).
 */
static uint32_t SubWord(uint32_t w) {
    uint8_t b[4] = {0};

    STORE32BE(b, w);

    b[0] = sBox[b[0]];
    b[1] = sBox[b[1]];
    b[2] = sBox[b[2]];
    b[3] = sBox[b[3]];

    return LOAD32BE(b);
}

/*
 * SubBytes transformation on AES state.
 * Each byte of the 4x4 state matrix is substituted with the S-box.
 * Provides non-linear diffusion for every round.
 */
static void SubBytes(uint8_t state[4][4]) {
    // Row 0
    state[0][0] = sBox[state[0][0]];
    state[0][1] = sBox[state[0][1]];
    state[0][2] = sBox[state[0][2]];
    state[0][3] = sBox[state[0][3]];

    // Row 1
    state[1][0] = sBox[state[1][0]];
    state[1][1] = sBox[state[1][1]];
    state[1][2] = sBox[state[1][2]];
    state[1][3] = sBox[state[1][3]];

    // Row 2
    state[2][0] = sBox[state[2][0]];
    state[2][1] = sBox[state[2][1]];
    state[2][2] = sBox[state[2][2]];
    state[2][3] = sBox[state[2][3]];

    // Row 3
    state[3][0] = sBox[state[3][0]];
    state[3][1] = sBox[state[3][1]];
    state[3][2] = sBox[state[3][2]];
    state[3][3] = sBox[state[3][3]];
}

/*
 * InvSubBytes – inverse S-box transformation.
 * Each byte of the state is replaced using the inverse S-box (rsBox).
 * Reverses the SubBytes operation during decryption.
 */
static void InvSubBytes(uint8_t state[4][4]) {
    // Row 0
    state[0][0] = rsBox[state[0][0]];
    state[0][1] = rsBox[state[0][1]];
    state[0][2] = rsBox[state[0][2]];
    state[0][3] = rsBox[state[0][3]];

    // Row 1
    state[1][0] = rsBox[state[1][0]];
    state[1][1] = rsBox[state[1][1]];
    state[1][2] = rsBox[state[1][2]];
    state[1][3] = rsBox[state[1][3]];

    // Row 2
    state[2][0] = rsBox[state[2][0]];
    state[2][1] = rsBox[state[2][1]];
    state[2][2] = rsBox[state[2][2]];
    state[2][3] = rsBox[state[2][3]];

    // Row 3
    state[3][0] = rsBox[state[3][0]];
    state[3][1] = rsBox[state[3][1]];
    state[3][2] = rsBox[state[3][2]];
    state[3][3] = rsBox[state[3][3]];
}

/*
 * ShiftRows transformation.
 * Rotates each row of the state by a fixed offset.
 * Row 0: unchanged
 * Row 1: left rotate 1
 * Row 2: left rotate 2
 * Row 3: left rotate 3
 * Enhances diffusion by moving bytes to different columns.
 */
static void ShiftRows(uint8_t state[4][4]) {
    uint8_t tmp;

    // Row 1: left rotate 1
    tmp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = tmp;

    // Row 2: left rotate 2
    tmp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = tmp;
    tmp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = tmp;

    // Row 3: left rotate 3 (equivalent to right rotate 1)
    tmp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = tmp;
}

/*
 * InvShiftRows – inverse of ShiftRows.
 * Rotates each row in the opposite direction.
 * Used in AES decryption to undo the diffusion step.
 */
static void InvShiftRows(uint8_t state[4][4]) {
    uint8_t tmp;

    // Row 1: right rotate 1
    tmp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = tmp;

    // Row 2: right rotate 2
    tmp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = tmp;
    tmp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = tmp;

    // Row 3: right rotate 3 (equivalent to left rotate 1)
    tmp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = tmp;
}

/*
 * MixColumns – mixes each column of the state.
 * Each byte in a column is replaced by a linear combination
 * of all 4 bytes in that column, using finite field multiplication.
 * Provides inter-column diffusion.
 */
static void MixColumns(uint8_t state[4][4]) {
    uint8_t a0, a1, a2, a3, t;

    // Column 0
    a0 = state[0][0]; a1 = state[1][0]; a2 = state[2][0]; a3 = state[3][0];
    t = a0 ^ a1 ^ a2 ^ a3;
    state[0][0] = a0 ^ t ^ XtimeByte(a0 ^ a1);
    state[1][0] = a1 ^ t ^ XtimeByte(a1 ^ a2);
    state[2][0] = a2 ^ t ^ XtimeByte(a2 ^ a3);
    state[3][0] = a3 ^ t ^ XtimeByte(a3 ^ a0);

    // Column 1
    a0 = state[0][1]; a1 = state[1][1]; a2 = state[2][1]; a3 = state[3][1];
    t = a0 ^ a1 ^ a2 ^ a3;
    state[0][1] = a0 ^ t ^ XtimeByte(a0 ^ a1);
    state[1][1] = a1 ^ t ^ XtimeByte(a1 ^ a2);
    state[2][1] = a2 ^ t ^ XtimeByte(a2 ^ a3);
    state[3][1] = a3 ^ t ^ XtimeByte(a3 ^ a0);

    // Column 2
    a0 = state[0][2]; a1 = state[1][2]; a2 = state[2][2]; a3 = state[3][2];
    t = a0 ^ a1 ^ a2 ^ a3;
    state[0][2] = a0 ^ t ^ XtimeByte(a0 ^ a1);
    state[1][2] = a1 ^ t ^ XtimeByte(a1 ^ a2);
    state[2][2] = a2 ^ t ^ XtimeByte(a2 ^ a3);
    state[3][2] = a3 ^ t ^ XtimeByte(a3 ^ a0);

    // Column 3
    a0 = state[0][3]; a1 = state[1][3]; a2 = state[2][3]; a3 = state[3][3];
    t = a0 ^ a1 ^ a2 ^ a3;
    state[0][3] = a0 ^ t ^ XtimeByte(a0 ^ a1);
    state[1][3] = a1 ^ t ^ XtimeByte(a1 ^ a2);
    state[2][3] = a2 ^ t ^ XtimeByte(a2 ^ a3);
    state[3][3] = a3 ^ t ^ XtimeByte(a3 ^ a0);
}

/*
 * InvMixColumns – inverse of MixColumns.
 * Each column is transformed using the inverse polynomial in GF(2^8).
 * Used during AES decryption to undo the linear mixing.
 */
static void InvMixColumns(uint8_t state[4][4]) {
    uint8_t a0, a1, a2, a3;

    // Column 0
    a0 = state[0][0]; a1 = state[1][0]; a2 = state[2][0]; a3 = state[3][0];
    state[0][0] = Mul(a0,0x0e) ^ Mul(a1,0x0b) ^ Mul(a2,0x0d) ^ Mul(a3,0x09);
    state[1][0] = Mul(a0,0x09) ^ Mul(a1,0x0e) ^ Mul(a2,0x0b) ^ Mul(a3,0x0d);
    state[2][0] = Mul(a0,0x0d) ^ Mul(a1,0x09) ^ Mul(a2,0x0e) ^ Mul(a3,0x0b);
    state[3][0] = Mul(a0,0x0b) ^ Mul(a1,0x0d) ^ Mul(a2,0x09) ^ Mul(a3,0x0e);

    // Column 1
    a0 = state[0][1]; a1 = state[1][1]; a2 = state[2][1]; a3 = state[3][1];
    state[0][1] = Mul(a0,0x0e) ^ Mul(a1,0x0b) ^ Mul(a2,0x0d) ^ Mul(a3,0x09);
    state[1][1] = Mul(a0,0x09) ^ Mul(a1,0x0e) ^ Mul(a2,0x0b) ^ Mul(a3,0x0d);
    state[2][1] = Mul(a0,0x0d) ^ Mul(a1,0x09) ^ Mul(a2,0x0e) ^ Mul(a3,0x0b);
    state[3][1] = Mul(a0,0x0b) ^ Mul(a1,0x0d) ^ Mul(a2,0x09) ^ Mul(a3,0x0e);

    // Column 2
    a0 = state[0][2]; a1 = state[1][2]; a2 = state[2][2]; a3 = state[3][2];
    state[0][2] = Mul(a0,0x0e) ^ Mul(a1,0x0b) ^ Mul(a2,0x0d) ^ Mul(a3,0x09);
    state[1][2] = Mul(a0,0x09) ^ Mul(a1,0x0e) ^ Mul(a2,0x0b) ^ Mul(a3,0x0d);
    state[2][2] = Mul(a0,0x0d) ^ Mul(a1,0x09) ^ Mul(a2,0x0e) ^ Mul(a3,0x0b);
    state[3][2] = Mul(a0,0x0b) ^ Mul(a1,0x0d) ^ Mul(a2,0x09) ^ Mul(a3,0x0e);

    // Column 3
    a0 = state[0][3]; a1 = state[1][3]; a2 = state[2][3]; a3 = state[3][3];
    state[0][3] = Mul(a0,0x0e) ^ Mul(a1,0x0b) ^ Mul(a2,0x0d) ^ Mul(a3,0x09);
    state[1][3] = Mul(a0,0x09) ^ Mul(a1,0x0e) ^ Mul(a2,0x0b) ^ Mul(a3,0x0d);
    state[2][3] = Mul(a0,0x0d) ^ Mul(a1,0x09) ^ Mul(a2,0x0e) ^ Mul(a3,0x0b);
    state[3][3] = Mul(a0,0x0b) ^ Mul(a1,0x0d) ^ Mul(a2,0x09) ^ Mul(a3,0x0e);
}

/*
 * AddRoundKey – XOR the state with the current round key.
 * Round key is represented as 4 32-bit words.
 * This is the main step where the key material influences the state.
 */
static void AddRoundKey(uint8_t state[4][4], const uint32_t roundKey[4]) {
    uint32_t rk_word;

    // Column 0
    rk_word = roundKey[0];
    state[0][0] ^= (uint8_t)((rk_word >> 24) & 0xFF);
    state[1][0] ^= (uint8_t)((rk_word >> 16) & 0xFF);
    state[2][0] ^= (uint8_t)((rk_word >> 8) & 0xFF);
    state[3][0] ^= (uint8_t)(rk_word & 0xFF);

    // Column 1
    rk_word = roundKey[1];
    state[0][1] ^= (uint8_t)((rk_word >> 24) & 0xFF);
    state[1][1] ^= (uint8_t)((rk_word >> 16) & 0xFF);
    state[2][1] ^= (uint8_t)((rk_word >> 8) & 0xFF);
    state[3][1] ^= (uint8_t)(rk_word & 0xFF);

    // Column 2
    rk_word = roundKey[2];
    state[0][2] ^= (uint8_t)((rk_word >> 24) & 0xFF);
    state[1][2] ^= (uint8_t)((rk_word >> 16) & 0xFF);
    state[2][2] ^= (uint8_t)((rk_word >> 8) & 0xFF);
    state[3][2] ^= (uint8_t)(rk_word & 0xFF);

    // Column 3
    rk_word = roundKey[3];
    state[0][3] ^= (uint8_t)((rk_word >> 24) & 0xFF);
    state[1][3] ^= (uint8_t)((rk_word >> 16) & 0xFF);
    state[2][3] ^= (uint8_t)((rk_word >> 8) & 0xFF);
    state[3][3] ^= (uint8_t)(rk_word & 0xFF);
}

/*
 * KeyExpansion – generates the round keys from the original AES key.
 * rk: pointer to output round key array (4*(Nr+1) words)
 * key: original user key bytes
 * keySize: length of user key (16, 24, 32 bytes)
 * rounds: number of AES rounds (10, 12, 14)
 */
static void KeyExpansion(uint32_t *rk, const uint8_t *key, size_t keySize, uint32_t rounds) {
    uint32_t Nk = (uint32_t)(keySize / 4); // Number of 32-bit words in key (4, 6, 8)

    // Copy initial key bytes directly into first Nk words of rk
    for (uint32_t i = 0; i < Nk; i++) {
        rk[i] = LOAD32BE(key + 4*i);
    }

    // Generate remaining round keys
    for (uint32_t i = Nk; i < 4 * (rounds + 1); i++) {
        uint32_t temp = rk[i - 1];

        if (i % Nk == 0) {
            // RotWord + SubWord + Rcon for first word in each key block
            temp = SubWord(RotWord(temp));
            temp ^= ((uint32_t)rCon[i / Nk] << 24);
        }
        else if (Nk > 6 && i % Nk == 4) {
            // AES-256 specific extra SubWord
            temp = SubWord(temp);
        }

        // XOR with word Nk positions before
        rk[i] = rk[i - Nk] ^ temp;
    }
}

/*
 * Cipher – encrypt a single 16-byte block using the AES round keys
 * rk: round key array
 * Nr: number of rounds
 * in: 16-byte input plaintext block
 * out: 16-byte output ciphertext block
 */
static void Cipher(const uint32_t *rk, uint32_t Nr, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]) {
    uint8_t state[4][4] = {0};

    // Load input into state (AES column-major order)
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            state[r][c] = in[c*4 + r];

    // Initial AddRoundKey (round 0)
    AddRoundKey(state, rk);

    // Main rounds 1..Nr-1
    for (uint32_t round = 1; round < Nr; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, &rk[round*4]);
    }

    // Final round (no MixColumns)
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, &rk[Nr*4]);

    // Copy state back to output
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            out[c*4 + r] = state[r][c];

    // Clear state from stack to prevent leakage
    SECURE_ZERO(state, sizeof(state));
}

/*
 * InvCipher – decrypt a single 16-byte block using AES round keys
 * rk: round key array
 * Nr: number of rounds
 * in: 16-byte ciphertext block
 * out: 16-byte plaintext block
 */
static void InvCipher(const uint32_t *rk, uint32_t Nr, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]) {
    uint8_t state[4][4] = {0};

    // Load input into state (column-major)
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            state[r][c] = in[c*4 + r];

    // Initial AddRoundKey with last round key
    AddRoundKey(state, &rk[Nr*4]);

    // Main rounds Nr-1 down to 1
    for (uint32_t round = Nr-1; round > 0; round--) {
        InvShiftRows(state); 
        InvSubBytes(state);
        AddRoundKey(state, &rk[round*4]);
        InvMixColumns(state);
    }

    // Final round (no InvMixColumns)
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, rk);

    // Copy state back to output
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            out[c*4 + r] = state[r][c];

    // Clear sensitive data
    SECURE_ZERO(state, sizeof(state));
}

/*
 * Initialize AES encryption key schedule.
 * Determines number of rounds based on key size and performs key expansion.
 */
bool ll_AES_SetEncryptKey(ll_AES_KEY *key, const uint8_t *userKey, size_t UserkeySize) {
    if (!key || !userKey) return false;

    SECURE_ZERO(key, sizeof(*key));

    // Set number of rounds based on key length
    switch (UserkeySize) {
        case AES_128_KEY_SIZE: key->Nr = AES_128_ROUNDS; break;
        case AES_192_KEY_SIZE: key->Nr = AES_192_ROUNDS; break;
        case AES_256_KEY_SIZE: key->Nr = AES_256_ROUNDS; break;
        default: return false;
    }

    KeyExpansion(key->rk, userKey, UserkeySize, key->Nr);
    return true;
}

/*
 * Initialize AES decryption key schedule.
 * Same expansion as encryption; InvCipher handles the inverse operations.
 */
bool ll_AES_SetDecryptKey(ll_AES_KEY *key, const uint8_t *userKey, size_t UserkeySize) {
    return ll_AES_SetEncryptKey(key, userKey, UserkeySize);
}

/*
 * Encrypt a single AES block.
 */
bool ll_AES_EncryptBlock(const ll_AES_KEY *key, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]) {
    if (!in || !out || !key) return false;

    Cipher(key->rk, key->Nr, in, out);
    return true;
}

/*
 * Decrypt a single AES block.
 */
bool ll_AES_DecryptBlock(const ll_AES_KEY *key, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]) {
    if (!in || !out || !key) return false;

    InvCipher(key->rk, key->Nr, in, out);
    return true;
}