#include "base32.h"

#define BASE32_PAD_CHAR '='

// Base32 encoding table (RFC 4648)
static const char BASE32_ENC_TABLE[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#define BASE32_MIN '2'
#define BASE32_MAX 'Z'

// Base32 reverse lookup table (shifted).
// This table maps ASCII characters '2' (50) to 'Z' (90) into Base32 values.
// Indexing: val = BASE32_REV_TABLE[ch - '2']
// - Valid Base32 chars map to 0..31
//   - 'A'-'Z' -> 0..25
//   - '2'-'7' -> 26..31
// - Invalid chars are -1
// - ignored chars (like '=' or '\n') are -2
static const int8_t BASE32_REV_TABLE[] = {
    // '2'-'7' (50-55)
    26,27,28,29,30,31,
    // '8'-'@' (56-64) → invalid
    -1,-1,-1,-1,-1,-2,-1,-1,-1,
    // 'A'-'Z' (65-90)
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25
};

bool ll_BASE32_Encode(const uint8_t *data, size_t data_len, char *out, size_t *out_len, uint32_t mode) {
    if (!data || data_len == 0 || !out || !out_len) return false;

    size_t index = 0;

    int noPad = ((mode & BASE32_ENC_NOPAD) != 0);

    for (size_t i = 0; i < data_len; i += 5) {
        uint8_t in0 = data[i];
        uint8_t in1 = (i + 1 < data_len) ? data[i + 1] : 0;
        uint8_t in2 = (i + 2 < data_len) ? data[i + 2] : 0;
        uint8_t in3 = (i + 3 < data_len) ? data[i + 3] : 0;
        uint8_t in4 = (i + 4 < data_len) ? data[i + 4] : 0;

        size_t rem = data_len - i;
        uint64_t buf = ((uint64_t)in0 << 32) | ((uint64_t)in1 << 24) | ((uint64_t)in2 << 16) |
                       ((uint64_t)in3 << 8) | ((uint64_t)in4);

        size_t total_bits = rem * 8;
        size_t chunks = (total_bits + 4) / 5; // number of 5-bit chunks

        for (int c = 0; c < 8; c++) {
            if (c < (int)chunks) {
                out[index++] = BASE32_ENC_TABLE[(buf >> (35 - c*5)) & 0x1F];
            } else if (!noPad) {
                out[index++] = BASE32_PAD_CHAR;
            }
        }
    }

    out[index] = '\0';
    *out_len = index;
    return true;
}

bool ll_BASE32_Decode(const char *data, size_t data_len, uint8_t *out, size_t *out_len, uint32_t mode) {
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

    int noPad = ((mode & BASE32_DEC_NOPAD) != 0);

    // Standard Base32 must be multiple of 8 unless noPad
    if (!noPad && data_len % BASE32_BLOCK_SIZE != 0) return false;

    size_t index = 0;
    uint64_t buf;

    for (size_t i = 0; i < data_len; i += 8) {
        buf = 0;
        int valid_chars = 0;

        // Read up to 8 input characters
        for (int j = 0; j < 8; j++) {
            char c = (i + (size_t)j < data_len) ? data[i + (size_t)j] : BASE32_PAD_CHAR;
            int8_t val = -1;

            if (c == BASE32_PAD_CHAR) {
                val = 0;
            }

            else if (c >= BASE32_MIN && c <= BASE32_MAX) val = BASE32_REV_TABLE[c - BASE32_MIN];

            if (val < 0) return false; // invalid char

            // Shift buffer MSB-first
            buf <<= 5;
            buf |= (uint64_t)val;

            if (c != BASE32_PAD_CHAR) valid_chars++;
            }
        
        if (valid_chars >= 2) out[index++] = (buf >> 32) & 0xFF;
        if (valid_chars >= 4) out[index++] = (buf >> 24) & 0xFF;
        if (valid_chars >= 5) out[index++] = (buf >> 16) & 0xFF;
        if (valid_chars >= 7) out[index++] = (buf >> 8) & 0xFF;
        if (valid_chars >= 8) out[index++] = buf & 0xFF;
    }

    *out_len = index;
    return true;
}
