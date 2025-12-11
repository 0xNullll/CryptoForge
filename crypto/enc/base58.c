/*
 * CryptoForge - Base58.c / Hex encoding and decoding functions
 * Copyright (C) 2025 0xNullll
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#include "base58.h"

#define BASE58_LEADING_ZERO '1'

static const char BASE58_ENC_TABLE[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

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

    // Approx max size: 0.733 * digits + 8, gives enough room for intermediate carry/overflow handling.
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