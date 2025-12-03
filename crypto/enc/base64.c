#include "base64.h"

#define BASE64_PAD_CHAR '='

// Base64 lookup table.  
static const char BASE64_ENC_TABLE[] = {
    'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
    'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
    'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
    'w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/'
};

// Base64 reverse lookup table (shifted).  
// This table maps ASCII characters '+' (43) to 'z' (122) into Base64 values.
// Indexing: val = BASE64_REV_TABLE[ch - '+']
// - Valid Base64 chars map to 0..63
// - Invalid chars are -1
// - -2 can optionally be used for special cases (like ignoring '\n')

// Table entries correspond to ASCII values starting at '+'
// Index 0  = '+' -> 62
// Index 1-3 = ',' '-' '.' -> invalid (-1)
// Index 4  = '/' -> 63
// Index 5-14 = '0'..'9' -> 52..61
// Index 15-16 = ':' ';' -> invalid (-1)
// Index 17 = '<' -> -2 (could be used for special ignored char)
// Index 18-43 = 'A'..'Z' -> 0..25
// Index 44-49 = '[' '\' ']' '^' '_' '`' -> invalid (-1)
// Index 50-75 = 'a'..'z' -> 26..51
static const char BASE64_REV_TABLE[] = {
    62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,
    -1,-1,-1,-2,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,10,
    11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,
    -1,-1,-1,-1,-1,-1,26,27,28,29,30,31,32,33,34,
    35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,
    50,51
};

bool ll_BASE64_Encode(const uint8_t *data, size_t data_len, char *out, size_t *out_len) {
    if (!data || data_len == 0 || !out || !out_len) return false;

    uint32_t buf;
    size_t index = 0;

    for (size_t i = 0; i < data_len; i += 3) {        
        uint8_t in[3] = {
            data[i],
            (i + 1 < data_len) ? data[i + 1] : 0,
            (i + 2 < data_len) ? data[i + 2] : 0
        };

        buf = 0;
        buf = (in[0] << 16) | (in[1] << 8) | in[2];

        size_t rem = data_len - i; // remaining bytes

        out[index++] = BASE64_ENC_TABLE[(buf >> 18) & 0x3F];
        out[index++] = BASE64_ENC_TABLE[(buf >> 12) & 0x3F];
        out[index++] = (rem > 1) ? BASE64_ENC_TABLE[(buf >> 6) & 0x3F] : BASE64_PAD_CHAR;
        out[index++] = (rem > 2) ? BASE64_ENC_TABLE[buf & 0x3F] : BASE64_PAD_CHAR;
    }

    out[index] = '\0';
    *out_len = index;

    return true;
}

bool ll_BASE64_Decode(const char *data, size_t data_len, uint8_t *out, size_t *out_len) {
    if (!data || data_len == 0 || !out || !out_len) return false;
    if (data_len % 4 != 0) return false; // Base64 input must be multiple of 4

    size_t index = 0;

    for (size_t i = 0; i < data_len; i += 4) {
        uint32_t buf = 0;
        for (uint8_t j = 0; j < 4; j++) {
            char c = data[i + j];
            int8_t val;

            if (c == BASE64_PAD_CHAR) {
                val = 0; // padding treated as zero in buffer
            } else if (c < '+' || c > 'z') {
                return false; // outside table range
            } else {
                val = BASE64_REV_TABLE[c - '+']; // shift ASCII to table index
                if (val < 0) return false;       // invalid character
            }

            buf |= (uint32_t)val << (18 - 6 * j);
        }

        out[index++] = (buf >> 16) & 0xFF;
        if (data[i + 2] != BASE64_PAD_CHAR) out[index++] = (buf >> 8) & 0xFF;
        if (data[i + 3] != BASE64_PAD_CHAR) out[index++] = buf & 0xFF;
    }

    *out_len = index;
    return true;
}