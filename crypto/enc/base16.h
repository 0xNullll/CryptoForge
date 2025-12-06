#ifndef BASE16_H
#define BASE16_H

#include "../../config/libs.h"
#include "../../utils/mem.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ENC_BASE16_UPPER    0x01  // '0'-'9','A'-'F'
#define ENC_BASE16_LOWER    0x04  // '0'-'9','a'-'f'

#define BASE16_ENC_LEN(data_len) ((size_t)(data_len) * 2 + 1)
#define BASE16_DEC_LEN(data_len) ((size_t)(data_len) / 2)

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