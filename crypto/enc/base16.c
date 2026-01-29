/*
 * CryptoForge - Base16.c / Hex encoding and decoding functions
 * Copyright (C) 2025 0xNullll
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the MIT License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * You should have received a copy of the MIT License along with this program.
 * If not, see <https://opensource.org/licenses/MIT>.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#include "../../include/crypto/base16.h"

// Hex encoding table
static const char BASE16_ENC_TABLE_UPPER[] = "0123456789ABCDEF";
static const char BASE16_ENC_TABLE_LOWER[] = "0123456789abcdef";

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

        if (c1 >= BASE16_MIN && c1 <= BASE16_MAX) hi = BASE16_REV_TABLE[c1 - BASE16_MIN];
        if (c2 >= BASE16_MIN && c2 <= BASE16_MAX) lo = BASE16_REV_TABLE[c2 - BASE16_MIN];

        if (hi < 0 || lo < 0) return false; // invalid hex char

        out[index++] = (uint8_t)((hi << 4) | lo);
    }

    *out_len = index;
    return true;
}
