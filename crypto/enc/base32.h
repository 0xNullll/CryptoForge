#ifndef BASE32_H
#define BASE32_H

#include "../../config/libs.h"
#include "../../utils/mem.h"

#ifdef __cplusplus
extern "C" {
#endif

// Base32 (RFC 4648) length macros
#define BASE32_ENC_LEN(data_len) (8 * (((size_t)(data_len) + 4) / 5) + 1) // +1 for '\0'
#define BASE32_DEC_LEN(data_len) (5 * ((size_t)(data_len) / 8))

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