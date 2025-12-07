#ifndef BASE85_H
#define BASE85_H

#include "../../config/libs.h"
#include "../../utils/mem.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BASE85_ENC_LEN(data_len) (((size_t)(data_len) + 3) / 4 * 5 + 1) // +1 for '\0'
#define BASE85_DEC_LEN(data_len) ((size_t)(data_len) / 5 * 4 + 4)

#define ENC_BASE85_STD  0x10000     // Standard ASCII85 ('z' supported)
#define DEC_BASE85_STD  0x20000
#define ENC_BASE85_EXT  0x40000     // Extended ASCII85 ('y' optional)
#define DEC_BASE85_EXT  0x80000
#define ENC_BASE85_Z85  0x100000    // Z85 variant (no z/y, different charset)
#define DEC_BASE85_Z85  0x200000
#define DEC_BASE85_WS   0x400000    // Ignore white spaces

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