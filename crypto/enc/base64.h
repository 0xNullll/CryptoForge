#ifndef BASE64_H
#define BASE64_H

#include "../../config/libs.h"
#include "../../utils/mem.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BASE64_PAD_CHAR '='

#define BASE64_MIN '+'
#define BASE64_URL_SAFE_MIN '-'
#define BASE64_MAX 'z'
#define BASE64_URL_SAFE_MAX 'z'

// Base64 reverse lookup table (shifted).  
// This table maps ASCII characters '+' (43) to 'z' (122) into Base64 values.
// Indexing: val = BASE64_REV_TABLE[ch - '+']
// - Valid Base64 chars map to 0..63
// - Invalid chars are -1
// - ignored chars (like '=' or '\n') are -2
static const int8_t BASE64_REV_TABLE[] = {
    62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,
    -1,-1,-1,-2,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,10,
    11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,
    -1,-1,-1,-1,-1,-1,26,27,28,29,30,31,32,33,34,
    35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,
    50,51
};

// Base64 safe-URL reverse lookup table (shifted).  
// This table maps ASCII characters '-' (45) to 'z' (122) into Base64 safe-URL values.
// Indexing: val = BASE64_REV_TABLE[ch - '-']
// - Valid Base64 chars map to 0..63
// - Invalid chars are -1
// - ignored chars (like '=' or '\n') are -2
static const int8_t BASE64_REV_URL_SAFE_TABLE[] = {
    62,-1,-1,52,53,54,55,56,57,58,59,60,61,
    -1,-1,-1,-1,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,10,
    11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,
    -1,-1,-1,-1,63,-1,26,27,28,29,30,31,32,33,34,
    35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,
    50,51
};

// Base64 (RFC 4648) length macros
#define BASE64_ENC_LEN(data_len) (4 * (((size_t)(data_len) + 2) / 3) + 2) // +2 for '\0' and safety
#define BASE64_DEC_LEN(data_len) (((size_t)(data_len) + 3) / 4 * 3 + 1) // +1 for safety

#define BASE64_BLOCK_SIZE 4

#define BASE64_STD_ENC       0x400    // Standard Base64
#define BASE64_STD_DEC       0x800
#define BASE64_URL_ENC       0x1000   // URL-safe Base64 with padding
#define BASE64_URL_DEC       0x2000
#define BASE64_NOPAD_ENC     0x4000   // URL-safe Base64 without padding
#define BASE64_NOPAD_DEC     0x8000

// Encode input buffer to Base64.
// 'out' must be large enough to hold the result
// 'out_len' will be set to the actual number of characters written.
bool ll_BASE64_Encode(
    const uint8_t *data, size_t data_len,
    char *out, size_t *out_len, uint32_t mode);

// Decode Base64 input buffer to raw bytes.
// 'out' must be large enough to hold the decoded bytes
// 'out_len' will be set to the actual number of bytes written.
bool ll_BASE64_Decode(
    const char *data, size_t data_len,
    uint8_t *out, size_t *out_len, uint32_t mode);

#ifdef __cplusplus
}
#endif

#endif // BASE64_H