#include "base85.h"

#define ASCII85_ZERO_SHORTCUT 'z'    // shortcut for 0x00000000
#define ASCII85_SPACE_SHORTCUT 'y'   // shortcut for 0x20202020

static const char BASE85_Z85_ENC_TABLE[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";

#define BASE85_ASCII85_MIN '!'
#define BASE85_Z85_MIN '!'
#define BASE85_ASCII85_MAX 'u'
#define BASE85_Z85_MAX '}'

// Base85 reverse lookup table (Ascii85).
// This table maps ASCII characters '!' (33) to 'u' (117) into Base85 values.
// Indexing: val = BASE85_ASCII85_REV_TABLE[ch - '!']
// - Valid Ascii85 chars map to 0..84
// - Table is sequential because Ascii85 digits are simply (ch - '!')
static const int8_t BASE85_ASCII85_REV_TABLE[] = {
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9,    // ! to )
   10, 11, 12, 13, 14, 15, 16, 17, 18, 19,    // * to +
   20, 21, 22, 23, 24, 25, 26, 27, 28, 29,    // , to 2
   30, 31, 32, 33, 34, 35, 36, 37, 38, 39,    // 3 to <
   40, 41, 42, 43, 44, 45, 46, 47, 48, 49,    // = to ?
   50, 51, 52, 53, 54, 55, 56, 57, 58, 59,    // @ to I
   60, 61, 62, 63, 64, 65, 66, 67, 68, 69,    // J to R
   70, 71, 72, 73, 74, 75, 76, 77, 78, 79,    // S to [
   80, 81, 82, 83, 84                         // \ to u
};

// Base85 reverse lookup table (Z85).
// This table maps ASCII characters '!' (33) to '}' (125) into Z85 values.
// Indexing: val = BASE85_Z85_REV_TABLE[ch - '!']
// - Valid Z85 chars map to 0..84
// - Table is not sequential like Ascii85; it follows the Z85 specification order
static const int8_t BASE85_Z85_REV_TABLE[] = {
    68, -1, 84, 83, 82, 72, -1, 75, 76, 70, 65, -1, 63, 62, 69, // offsets 0-14
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, // '0'-'9' offsets 15-24
    64, -1, 73, 66, 74, 71, 81,   // offsets 25-31
    36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, // 'A'-'Z' offsets 32-57
    77, -1, 78, 67, -1, -1, // punctuation offsets 58-63
    10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, // 'a'-'z' offsets 64-89
    79, -1, 80  // '{', '}', offsets 90-92
};

static FORCE_INLINE void write_u32_be(uint8_t *out, uint32_t value) {
    // Manual big-endian
    out[0] = (uint8_t)((value >> 24) & 0xFF);
    out[1] = (uint8_t)((value >> 16) & 0xFF);
    out[2] = (uint8_t)((value >> 8) & 0xFF);
    out[3] = (uint8_t)(value & 0xFF);
}

static FORCE_INLINE uint32_t read_u32_be(const uint8_t *in) {
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) | in[3];
}

// --- Encode Base85 / Z85 ---
bool ll_BASE85_Encode(const uint8_t *data, size_t data_len, char *out, size_t *out_len, uint32_t mode) {
    if (!data || !out || !out_len) return false;

    bool isZ85 = (mode & BASE85_Z85_ENC) != 0;
    bool useExt = (mode & BASE85_EXT_ENC) != 0;

    if (isZ85) {
        // Z85 requires input length multiple of 4
        if (data_len % BASE85_Z85_IN_BLOCK_SIZE != 0) {
            return false;  // cannot encode
        }
    }

    size_t index = 0;
    size_t i = 0;

    // Full 4-byte blocks
    for (; i + 3 < data_len; i += 4) {
        uint32_t buf = read_u32_be(data + i);

        // Shortcuts
        if (!isZ85 && buf == 0) {
            out[index++] = 'z';
            continue;
        }
        
        if (!isZ85 && useExt && buf == 0x20202020) {
            out[index++] = 'y';
            continue;
        }

        uint32_t tmp = buf;
        char enc[5];

        for (int j = 4; j >= 0; j--) {
            enc[j] = (char)(tmp % 85);
            tmp /= 85;
        }

        for (int j = 0; j < 5; j++) {
            if (isZ85) enc[j] = BASE85_Z85_ENC_TABLE[(unsigned char)enc[j]];
            else enc[j] += 33;
        }

        SECURE_MEMCPY(out + index, enc, 5);
        index += 5;
    }

    // Partial tail
    size_t tail = data_len - i;
    if (!isZ85 && tail > 0) {
        uint32_t buf = 0;
        for (size_t j = 0; j < tail; j++) buf |= (uint32_t)data[i + j] << (24 - 8 * j);

        uint32_t tmp = buf;
        char enc[5];
        for (int j = 4; j >= 0; j--) {
            enc[j] = (char)(tmp % 85);
            tmp /= 85;
        }

        for (int j = 0; j < 5; j++) {
            enc[j] += 33;
        }

        for (size_t j = 0; j < tail + 1; j++) {
            out[index++] = enc[j];
        }
    }

    *out_len = index;
    return true;
}

// // --- Decode Base85 / Z85 ---
bool ll_BASE85_Decode(const char *data, size_t data_len, uint8_t *out, size_t *out_len, uint32_t mode) {
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

    bool isZ85 = (mode & BASE85_Z85_DEC) != 0;
    bool useExt = (mode & BASE85_EXT_DEC) != 0;

    if (isZ85) {
        // Z85 decoding requires input length multiple of 5 characters
        if (data_len % BASE85_Z85_OUT_BLOCK_SIZE != 0) {
            return false;  // invalid input length for Z85
        }
    }

    const int8_t *rev_table = isZ85 ? BASE85_Z85_REV_TABLE : BASE85_ASCII85_REV_TABLE;
    char min_char = isZ85 ? BASE85_Z85_MIN : BASE85_ASCII85_MIN;
    char max_char = isZ85 ? BASE85_Z85_MAX : BASE85_ASCII85_MAX;

    size_t index = 0;
    uint32_t value = 0;
    int count = 0;

    for (size_t i = 0; i < data_len; i++) {
        char c = data[i];

        // Ignore whitespace if flag is set
        if ((mode & BASE85_IGNORE_WS) && isspace((unsigned char)c)) continue;

        // Shortcuts (ASCII85 only)
        if (!isZ85 && c == ASCII85_ZERO_SHORTCUT && count == 0) { 
            write_u32_be(out + index, 0); 
            index += 4; 
            continue; 
        }
        if (!isZ85 && useExt && c == ASCII85_SPACE_SHORTCUT && count == 0) { 
            write_u32_be(out + index, 0x20202020); 
            index += 4; 
            continue; 
        }

        // Convert char -> value
        int val = -1;
        if ((unsigned char)c >= (unsigned char)min_char && (unsigned char)c <= (unsigned char)max_char) {
            val = rev_table[(unsigned char)c - (unsigned char)min_char];
        }
        if (val < 0) {
            return false; // invalid character
        }

        value = value * 85 + (uint32_t)val;
        count++;

        if (count == 5) {
            write_u32_be(out + index, value);
            index += 4;
            value = 0;
            count = 0;
        }
    }

    // Handle partial final block (ASCII85 only)
    if (!isZ85 && count > 0) {
        for (int j = count; j < 5; j++) {
            value = value * 85 + 84; // pad with 'u'
        }
        for (int j = 0; j < count - 1; j++) {
            out[index + (size_t)j] = (uint8_t)(value >> (24 - j * 8));
        }
        index += (size_t)(count - 1);
    } else if (isZ85 && count != 0) {
        // Z85 cannot have partial blocks
        return false;
    }

    *out_len = index;
    return true;
}