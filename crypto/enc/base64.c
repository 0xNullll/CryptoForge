#include "base64.h"

#define BASE64_PAD_CHAR '='

// Base64 lookup table.  
static const char BASE64_ENC_TABLE[] = {
    'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
    'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
    'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
    'w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/'
};

static const char BASE64_ENC_URL_SAFE_TABLE[] = {
    'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
    'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
    'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
    'w','x','y','z','0','1','2','3','4','5','6','7','8','9','-','_'
};

// Base64 reverse lookup table (shifted).  
// This table maps ASCII characters '+' (43) to 'z' (122) into Base64 values.
// Indexing: val = BASE64_REV_TABLE[ch - '+']
// - Valid Base64 chars map to 0..63
// - Invalid chars are -1
// - ignored chars (like '=' or '\n') are -2
static const char BASE64_REV_TABLE[] = {
    62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,
    -1,-1,-1,-2,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,10,
    11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,
    -1,-1,-1,-1,-1,-1,26,27,28,29,30,31,32,33,34,
    35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,
    50,51
};

// Base64 safe-URL reverse lookup table (shifted).  
// This table maps ASCII characters '-' (45) to 'z' (122) into Base64 safe-URL values.
// Indexing: val = BASE64_REV_TABLE[ch - '-']
// - Valid Base64 chars map to 0..63
// - Invalid chars are -1
// - ignored chars (like '=' or '\n') are -2
static const char BASE64_REV_URL_SAFE_TABLE[] = {
    62,-1,-1,52,53,54,55,56,57,58,59,60,61,
    -1,-1,-1,-2,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,10,
    11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,
    -1,-1,-1,-1,-1,-1,26,27,28,29,30,31,32,33,34,
    35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,
    50,51,63
};

bool ll_BASE64_Encode(const uint8_t *data, size_t data_len, char *out, size_t *out_len, uint32_t mode) {
    if (!data || data_len == 0 || !out || !out_len) return false;

    int noPad = ((mode & ENC_BASE64_URL_NOPAD) != 0);
    int isUrlSafe = ((mode & ENC_BASE64_URL) != 0 || (mode & ENC_BASE64_URL_NOPAD) != 0);

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

    int noPad = ((mode & DEC_BASE64_URL_NOPAD) != 0);
    int isUrlSafe = ((mode & DEC_BASE64_URL) != 0 || (mode & DEC_BASE64_URL_NOPAD) != 0);

    // Standard Base64 must be multiple of 4 unless padding is omitted
    if (!isUrlSafe && !noPad && data_len % 4 != 0) 
        return false;

    size_t index = 0;

    for (size_t i = 0; i < data_len; i += 4) {
        uint32_t buf = 0;
        int valid_chars = 0;

        for (int j = 0; j < 4; j++) {
            char c = (i + (size_t)j < data_len) ? data[i + (size_t)j] : BASE64_PAD_CHAR;
            int8_t val = -1;

            if (c == BASE64_PAD_CHAR) {
                val = 0;
            } else if (!isUrlSafe) {
                if (c >= '+' && c <= 'z') val = BASE64_REV_TABLE[c - '+'];
            } else {
                if (c >= '-' && c <= 'z') val = BASE64_REV_URL_SAFE_TABLE[c - '-'];
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
