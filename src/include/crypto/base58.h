/*
 * CryptoForge - Base58.h / Hex encoding and decoding functions
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

#ifndef BASE58_H
#define BASE58_H

#include "../config/libs.h"
#include "../utils/mem.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BASE58_MIN '1'
#define BASE58_MAX 'z'

// Base58 reverse lookup table (shifted).
// This table maps ASCII characters '1' (49) to 'z' (122) into Base58 values.
// Indexing: val = BASE58_REV_TABLE[ch - '1']
// - Valid Base58 chars map to 0..57
//   - '1'-'9'   -> 0..8
//   - 'A'-'H', 'J'-'N', 'P'-'Z' -> 9..32
//   - 'a'-'k', 'm'-'z' -> 33..57
// - Invalid chars are -1
static const int8_t BASE58_REV_TABLE[] = {
     0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,-1,
     9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,22,
    23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,-1,
    33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,47,
    48,49,50,51,52,53,54, 55,56,57
};

// Maximum Base58 encoded length for `data_len` bytes
// ceil(data_len * log(256)/log(58)) + 2 for '\0' and leading zeros
#define BASE58_ENC_LEN(data_len) ((size_t)((data_len) * 138 / 100 + 2))

// Maximum decoded length for Base58 string of `str_len` characters
// ceil(str_len * log(58)/log(256)) +8 bytes gives enough room for intermediate carry/overflow handling.
#define BASE58_DEC_LEN(str_len)  ((size_t)((str_len) * 733 / 1000 + 8))

//
// Maximum input size to use stack buffer
//
#define BASE58_MAX_STACK_INPUT 128

// Maximum output buffer needed for that input
#define BASE58_MAX_STACK_BUF (BASE58_ENC_LEN(BASE58_MAX_STACK_INPUT) + 4)

// Encode input buffer to Base58.
// 'out' must be large enough to hold the result
// 'out_len' will be set to the actual number of characters written.
bool ll_BASE58_Encode(
    const uint8_t *data, size_t data_len,
    char *out, size_t *out_len);

// Decode Base58 input buffer to raw bytes.
// 'out' must be large enough to hold the decoded bytes
// 'out_len' will be set to the actual number of bytes written.
bool ll_BASE58_Decode(
    const char *data, size_t data_len,
    uint8_t *out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif // BASE58_H