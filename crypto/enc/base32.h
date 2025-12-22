/*
 * CryptoForge - Base32.h / Hex encoding and decoding functions
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

#ifndef BASE32_H
#define BASE32_H

#include "../../config/libs.h"
#include "../../utils/mem.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BASE32_PAD_CHAR '='

#define BASE32_MIN '2'
#define BASE32_MAX 'Z'

// Base32 reverse lookup table (shifted).
// This table maps ASCII characters '2' (50) to 'Z' (90) into Base32 values.
// Indexing: val = BASE32_REV_TABLE[ch - '2']
// - Valid Base32 chars map to 0..31
//   - 'A'-'Z' -> 0..25
//   - '2'-'7' -> 26..31
// - Invalid chars are -1
// - ignored chars (like '=' or '\n') are -2
static const int8_t BASE32_REV_TABLE[] = {
    // '2'-'7' (50-55)
    26,27,28,29,30,31,
    // '8'-'@' (56-64) → invalid
    -1,-1,-1,-1,-1,-2,-1,-1,-1,
    // 'A'-'Z' (65-90)
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25
};

// Base32 (RFC 4648) length macros
#define BASE32_ENC_LEN(data_len) (8 * (((size_t)(data_len) + 4) / 5) + 2) // +2 for '\0'
#define BASE32_DEC_LEN(data_len) (((size_t)(data_len) * 5 + 7) / 8 + 1) // +1 for safety

#define BASE32_BLOCK_SIZE 8

#define BASE32_ENC        0x10
#define BASE32_DEC        0x20
#define BASE32_ENC_NOPAD  0x40
#define BASE32_DEC_NOPAD  0x80

// Encode input buffer to Base32.
// 'out' must be large enough to hold the result
// 'out_len' will be set to the actual number of characters written.
bool ll_BASE32_Encode(
    const uint8_t *data, size_t data_len,
    char *out, size_t *out_len, uint32_t mode);

// Decode Base32 input buffer to raw bytes.
// 'out' must be large enough to hold the decoded bytes
// 'out_len' will be set to the actual number of bytes written.
bool ll_BASE32_Decode(
    const char *data, size_t data_len,
    uint8_t *out, size_t *out_len, uint32_t mode);

#ifdef __cplusplus
}
#endif

#endif // BASE32_H