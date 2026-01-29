/*
 * CryptoForge - Base16.h / Hex encoding and decoding functions
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

#ifndef BASE16_H
#define BASE16_H

#include "../config/libs.h"
#include "../utils/mem.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BASE16_MIN '0'
#define BASE16_MAX 'f'

// Base16 reverse lookup table (shifted).
// This table maps ASCII characters '0' (48) to 'f' (102) into Base16 values.
// Indexing: val = BASE16_REV_TABLE[ch - '0']
// Valid:
//  - '0'-'9' -> 0..9
//  - 'A'-'F' -> 10..15
//  - 'a'-'f' -> 10..15
// - Invalid chars are -1
static const int8_t BASE16_REV_TABLE[] = {
    // '0'-'9' (48-57)
     0,1,2,3,4,5,6,7,8,9,
    // ':'- '@' (58-64) -> invalid
    -1,-1,-1,-1,-1,-1,-1,
    // 'A'-'F' (65-70)
    10,11,12,13,14,15,
    // 'G'-'`' (71-96) -> mostly invalid
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,
    // 'a'-'f' (97-102)
    10,11,12,13,14,15
};

// Base16 (RFC 3548) length macros
#define BASE16_ENC_LEN(data_len) (((size_t)(data_len) * 2) + 2)  // +2 for '\0' and safety
#define BASE16_DEC_LEN(data_len) ((size_t)(data_len) / 2 + 1) // +1 for safety

#define BASE16_BLOCK_SIZE 2

#define BASE16_UPPER    0x01  // '0'-'9','A'-'F'
#define BASE16_LOWER    0x02  // '0'-'9','a'-'f'

// Encode input buffer to Base16.
// 'out' must be large enough to hold the result
// 'out_len' will be set to the actual number of characters written.
bool ll_BASE16_Encode(
    const uint8_t *data, size_t data_len,
    char *out, size_t *out_len, uint32_t mode);

// Decode Base16 input buffer to raw bytes.
// 'out' must be large enough to hold the decoded bytes
// 'out_len' will be set to the actual number of bytes written.
bool ll_BASE16_Decode(
    const char *data, size_t data_len,
    uint8_t *out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif // BASE16_H