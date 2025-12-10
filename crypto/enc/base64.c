#include "base64.h"

// Base64 lookup table.  
static const char BASE64_ENC_TABLE[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const char BASE64_ENC_URL_SAFE_TABLE[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

bool ll_BASE64_Encode(const uint8_t *data, size_t data_len, char *out, size_t *out_len, uint32_t mode) {
    if (!data || data_len == 0 || !out || !out_len) return false;

    int noPad = ((mode & BASE64_NOPAD_ENC) != 0);
    int isUrlSafe = ((mode & BASE64_URL_ENC) != 0);

    const char *table = isUrlSafe ? BASE64_ENC_URL_SAFE_TABLE : BASE64_ENC_TABLE;
    size_t index = 0;

    for (size_t i = 0; i < data_len; i += 3) {
        uint8_t in0 = data[i];
        uint8_t in1 = (i + 1 < data_len) ? data[i + 1] : 0;
        uint8_t in2 = (i + 2 < data_len) ? data[i + 2] : 0;

        uint32_t buf = (in0 << 16) | (in1 << 8) | in2;
        size_t rem = data_len - i;

        // Always write first two characters
        out[index++] = table[(buf >> 18) & 0x3F];
        out[index++] = table[(buf >> 12) & 0x3F];

        // Third character
        if (rem > 1) {
            out[index++] = table[(buf >> 6) & 0x3F];
        } else if (!noPad) {
            out[index++] = BASE64_PAD_CHAR;
        }

        // Fourth character
        if (rem > 2) {
            out[index++] = table[buf & 0x3F];
        } else if (!noPad) {
            out[index++] = BASE64_PAD_CHAR;
        }
    }

    out[index] = '\0';
    *out_len = index;
    return true;
}

bool ll_BASE64_Decode(const char *data, size_t data_len, uint8_t *out, size_t *out_len, uint32_t mode) {
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

    bool isStd = (mode & BASE64_STD_DEC) != 0;
    bool isUrlSafe = (mode & BASE64_URL_DEC) != 0;
    bool noPad = (mode & BASE64_NOPAD_DEC) != 0;

    // Only check padding rules if standard Base64 or URL-safe with padding
    if ((isStd || isUrlSafe) && !noPad && (data_len % BASE64_BLOCK_SIZE != 0)) {
        return false; // invalid length
    }

    const char start_char = isUrlSafe ? BASE64_URL_SAFE_MIN : BASE64_MIN;
    const char max_char = isUrlSafe ? BASE64_URL_SAFE_MAX : BASE64_MAX;
    const int8_t *rev_table = isUrlSafe ? BASE64_REV_URL_SAFE_TABLE : BASE64_REV_TABLE;

    size_t index = 0;

    for (size_t i = 0; i < data_len; i += 4) {
        uint32_t buf = 0;
        int valid_chars = 0;

        for (int j = 0; j < 4; j++) {
            char c = (i + (size_t)j < data_len) ? data[i + (size_t)j] : BASE64_PAD_CHAR;
            int8_t val = -1;

            if (c == BASE64_PAD_CHAR) {
                val = 0;
            } else {
                if (c >= start_char && c <= max_char) val = rev_table[c - start_char];
            }

            if (val < 0) return false; // invalid char

            buf |= (uint32_t)val << (18 - 6 * j);

            if (c != BASE64_PAD_CHAR) valid_chars++;
        }

        // Write decoded bytes based on number of valid chars
        if (valid_chars >= 2) out[index++] = (buf >> 16) & 0xFF;
        if (valid_chars >= 3) out[index++] = (buf >> 8) & 0xFF;
        if (valid_chars >= 4) out[index++] = buf & 0xFF;
    }

    *out_len = index;
    return true;
}
