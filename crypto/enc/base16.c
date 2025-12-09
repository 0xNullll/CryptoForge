#include "base16.h"

// Hex encoding table
static const char BASE16_ENC_TABLE_UPPER[] = "0123456789ABCDEF";
static const char BASE16_ENC_TABLE_LOWER[] = "0123456789abcdef";

#define BASE32_MIN '0'
#define BASE32_MAX 'f'

// Base16 reverse lookup table (shifted).
// This table maps ASCII characters '0' (48) to 'f' (102) into Base16 values.
// Indexing: val = BASE32_REV_TABLE[ch - '0']
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

bool ll_BASE16_Encode(const uint8_t *data, size_t data_len,
                      char *out, size_t *out_len, uint32_t mode) {
    if (!data || data_len == 0 || !out || !out_len) return false;

    const char *table = (mode == BASE16_LOWER)
                        ? BASE16_ENC_TABLE_LOWER
                        : BASE16_ENC_TABLE_UPPER;

    size_t index = 0;

    for (size_t i = 0; i < data_len; i++) {
        uint8_t byte = data[i];

        out[index++] = table[(byte >> 4) & 0x0F]; // high nibble
        out[index++] = table[ byte       & 0x0F]; // low nibble
    }

    out[index] = '\0';
    *out_len = index;
    return true;
}

bool ll_BASE16_Decode(const char *data, size_t data_len, uint8_t *out, size_t *out_len) {
    if (!data || data_len == 0 || !out || !out_len) return false;

#if BASE_TRUNCATE_ON_NULL
    // Adjust data_len if null terminator appears before
    for (size_t i = 0; i < data_len; ++i) {
        if (data[i] == '\0') {
            data_len = i;
            break;
        }
    }
#endif // BASE_TRUNCATE_ON_NULL

    // Must be even number of characters
    if (data_len % BASE16_BLOCK_SIZE != 0) return false;

    size_t index = 0;

    for (size_t i = 0; i < data_len; i += 2) {
        char c1 = data[i];
        char c2 = data[i + 1];

        int8_t hi = -1;
        int8_t lo = -1;

        if (c1 >= BASE32_MIN && c1 <= BASE32_MAX) hi = BASE16_REV_TABLE[c1 - BASE32_MIN];
        if (c2 >= BASE32_MIN && c2 <= BASE32_MAX) lo = BASE16_REV_TABLE[c2 - BASE32_MIN];

        if (hi < 0 || lo < 0) return false; // invalid hex char

        out[index++] = (uint8_t)((hi << 4) | lo);
    }

    *out_len = index;
    return true;
}
