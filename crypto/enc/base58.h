#ifndef BASE58_H
#define BASE58_H

#include "../../config/libs.h"
#include "../../utils/mem.h"

#ifdef __cplusplus
extern "C" {
#endif

// Maximum Base58 encoded length for `data_len` bytes
// ceil(data_len * log(256)/log(58)) + 1 for '\0' and leading zeros
#define BASE58_ENC_LEN(data_len) ((size_t)((data_len) * 138 / 100 + 2))

// Maximum decoded length for Base58 string of `str_len` characters
// ceil(str_len * log(58)/log(256)) + 1 for safety
#define BASE58_DEC_LEN(str_len)  ((size_t)((str_len) * 733 / 1000 + 1))

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