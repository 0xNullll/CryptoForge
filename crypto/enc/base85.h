#ifndef BASE85_H
#define BASE85_H

#include "../../config/libs.h"
#include "../../utils/mem.h"

#ifdef __cplusplus
extern "C" {
#endif

// Base85 encoding length (works for ASCII85 and Z85)
#define BASE85_ENC_LEN(data_len) (((size_t)(data_len) + 3) / 4 * 5 + 1) // +1 for '\0'

// Base85 decoding length (safe for ASCII85, Z85)
#define BASE85_DEC_LEN(data_len) ((size_t)(data_len) / 5 * 4 + 4) // // +4 for possible partial block in ASCII85

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