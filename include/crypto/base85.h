/*
 * CryptoForge - Base85.h / Hex encoding and decoding functions
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against WyChaProof test vectors. No hardware optimizations. Use with caution.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#ifndef BASE85_H
#define BASE85_H

#include "../config/libs.h"
#include "../utils/mem.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BASE85_ASCII85_MIN '!'
#define BASE85_Z85_MIN '!'
#define BASE85_ASCII85_MAX 'u'
#define BASE85_Z85_MAX '}'

// Base85 reverse lookup table (Ascii85).
// This table maps ASCII characters '!' (33) to 'u' (117) into Base85 values.
// Indexing: val = BASE85_ASCII85_REV_TABLE[ch - '!']
// - Valid Ascii85 chars map to 0..84
// - Table is sequential because Ascii85 digits are simply (ch - '!')
static const int8_t BASE85_ASCII85_REV_TABLE[] = {
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9,    // ! to )
   10, 11, 12, 13, 14, 15, 16, 17, 18, 19,    // * to +
   20, 21, 22, 23, 24, 25, 26, 27, 28, 29,    // , to 2
   30, 31, 32, 33, 34, 35, 36, 37, 38, 39,    // 3 to <
   40, 41, 42, 43, 44, 45, 46, 47, 48, 49,    // = to ?
   50, 51, 52, 53, 54, 55, 56, 57, 58, 59,    // @ to I
   60, 61, 62, 63, 64, 65, 66, 67, 68, 69,    // J to R
   70, 71, 72, 73, 74, 75, 76, 77, 78, 79,    // S to [
   80, 81, 82, 83, 84                         // \ to u
};

// Base85 reverse lookup table (Z85).
// This table maps ASCII characters '!' (33) to '}' (125) into Z85 values.
// Indexing: val = BASE85_Z85_REV_TABLE[ch - '!']
// - Valid Z85 chars map to 0..84
// - Table is not sequential like Ascii85; it follows the Z85 specification order
static const int8_t BASE85_Z85_REV_TABLE[] = {
    68, -1, 84, 83, 82, 72, -1, 75, 76, 70, 65, -1, 63, 62, 69, // offsets 0-14
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, // '0'-'9' offsets 15-24
    64, -1, 73, 66, 74, 71, 81,   // offsets 25-31
    36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, // 'A'-'Z' offsets 32-57
    77, -1, 78, 67, -1, -1, // punctuation offsets 58-63
    10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, // 'a'-'z' offsets 64-89
    79, -1, 80  // '{', '}', offsets 90-92
};

// ASCII85
#define ASCII85_ENC_LEN(data_len) (((size_t)(data_len) + 3) / 4 * 5 + 2) // +2 for '\0' and safety
#define ASCII85_DEC_LEN(data_len) ((size_t)(data_len) / 5 * 4 + 4 + 1) // +1 for safety

// Z85
#define Z85_ENC_LEN(data_len) (((size_t)(data_len) / 4) * 5 + 2) // +2 for '\0' and safety
#define Z85_DEC_LEN(data_len) ((size_t)(data_len) / 5 * 4 + 1) // +1 for safety

#define BASE85_Z85_IN_BLOCK_SIZE   4
#define BASE85_Z85_OUT_BLOCK_SIZE  5

#define BASE85_STD_ENC   0x10000      // Standard ASCII85 ('z' supported)
#define BASE85_STD_DEC   0x20000
#define BASE85_EXT_ENC   0x40000      // Extended ASCII85 ('y' optional)
#define BASE85_EXT_DEC   0x80000
#define BASE85_Z85_ENC   0x100000     // Z85 variant (no z/y, different charset)
#define BASE85_Z85_DEC   0x200000
#define BASE85_IGNORE_WS 0x400000     // Ignore white spaces

// Encode input buffer to Base85.
// 'out' must be large enough to hold the result
// 'out_len' will be set to the actual number of characters written.
bool ll_BASE85_Encode(
    const uint8_t *data, size_t data_len,
    char *out, size_t *out_len, uint32_t mode);

// Decode Base85 input buffer to raw bytes.
// 'out' must be large enough to hold the decoded bytes
// 'out_len' will be set to the actual number of bytes written.
bool ll_BASE85_Decode(
    const char *data, size_t data_len,
    uint8_t *out, size_t *out_len, uint32_t mode);

#ifdef __cplusplus
}
#endif

#endif // BASE85_H