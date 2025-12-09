#ifndef BASE64_H
#define BASE64_H

#include "../../config/libs.h"
#include "../../utils/mem.h"

#ifdef __cplusplus
extern "C" {
#endif

// Base64 (RFC 4648) length macros
#define BASE64_ENC_LEN(data_len) (4 * (((size_t)(data_len) + 2) / 3) + 1) // +1 for '\0'
#define BASE64_DEC_LEN(data_len) (3 * ((size_t)(data_len) / 4))

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