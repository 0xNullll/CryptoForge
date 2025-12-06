#include "base58.h"

#define BASE58_LEADING_ZERO '1'

static const char BASE58_ENC_TABLE[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

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

bool ll_BASE58_Encode(const uint8_t *data, size_t data_len, char *out, size_t *out_len) {
    if (!data || data_len == 0 || !out || !out_len) return false;

    size_t zcount = 0; // count leading zeros
    while (zcount < data_len && data[zcount] == 0) zcount++;

    // Approx max size: log(256)/log(58) ≈ 1.38
    size_t size = BASE58_ENC_LEN(data_len - zcount);
    uint8_t buf[size];
    SECURE_ZERO(buf, size);

    size_t i, j, high;
    for (i = zcount, high = size - 1; i < data_len; ++i, high = j) {
        int val = data[i];
        for (j = size - 1; (j > high) || val; --j) {
            val += 256 * buf[j];
            buf[j] = (uint8_t)(val % 58);
            val /= 58;
            if (!j) break;
        }
    }

    // skip leading zeros in buf
    for (j = 0; j < size && buf[j] == 0; ++j);

    // check output buffer size
    if (*out_len <= zcount + size - j) {
        *out_len = zcount + size - j + 1; // required size
        return false;
    }

    // leading '1's for zeros
    for (i = 0; i < zcount; ++i) out[i] = BASE58_LEADING_ZERO;

    // convert buf -> chars
    for (; j < size; ++i, ++j) {
        out[i] = BASE58_ENC_TABLE[buf[j]];
    }

    out[i] = '\0';
    *out_len = i;
    return true;
}

bool ll_BASE58_Decode(const char *data, size_t data_len, uint8_t *out, size_t *out_len) {
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

    // Count leading '1's -> map to leading zeros
    size_t zcount = 0;
    while (zcount < data_len && data[zcount] == BASE58_LEADING_ZERO) zcount++;

    // Approx max size: 0.733 * digits
    size_t size = BASE58_DEC_LEN(data_len - zcount);
    uint8_t buf[size];
    SECURE_ZERO(buf, size);

    // Convert Base58 digits to big integer in buf
    for (size_t i = zcount; i < data_len; ++i) {
        int val = -1;
        char c = data[i];
        if (c >= BASE58_MIN && c <= BASE58_MAX) val = BASE58_REV_TABLE[c - BASE58_MIN]; // reverse lookup
        if (val < 0) return false; // invalid char

        for (size_t j = size - 1; j != (size_t)-1; --j) {
            val += 58 * buf[j];
            buf[j] = (uint8_t)(val & 0xFF);
            val >>= 8;
        }
    }

    // Skip leading zeros in buf
    size_t j = 0;
    while (j < size && buf[j] == 0) j++;

    size_t out_index = 0;

    // Leading zeros from '1's
    for (size_t i = 0; i < zcount; ++i) out[out_index++] = 0;

    // Copy remaining bytes
    for (; j < size; ++j) out[out_index++] = buf[j];

    *out_len = out_index;
    return true;
}