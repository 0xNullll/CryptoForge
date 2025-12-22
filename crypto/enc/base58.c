/*
 * CryptoForge - Base58.c / Hex encoding and decoding functions
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

#include "base58.h"

#define BASE58_LEADING_ZERO '1'

static const char BASE58_ENC_TABLE[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

bool ll_BASE58_Encode(const uint8_t *data, size_t data_len, char *out, size_t *out_len) {
    if (!data || data_len == 0 || !out || !out_len) return false;

    // Count leading zero bytes
    size_t zcount = 0;
    while (zcount < data_len && data[zcount] == 0)
        zcount++;

    // All-zero input -> only '1's
    if (zcount == data_len) {
        if (*out_len <= zcount) {
            *out_len = zcount + 1;
            return false;
        }
        for (size_t i = 0; i < zcount; ++i)
            out[i] = BASE58_LEADING_ZERO;
        out[zcount] = '\0';
        *out_len = zcount;
        return true;
    }

    size_t required_size = BASE58_ENC_LEN(data_len - zcount + 2);
    if (required_size == 0) return false; // defensive

    uint8_t stack_buf[BASE58_MAX_STACK_BUF];
    uint8_t *buf = stack_buf;
    bool heap_used = false;

    if (data_len > BASE58_MAX_STACK_INPUT) {
        buf = malloc(required_size);
        if (!buf) return false;
        heap_used = true;
    }

    SECURE_ZERO(buf, required_size);

    size_t high = required_size - 1;

    for (size_t i = zcount; i < data_len; ++i) {
        int val = data[i];

        for (size_t j = required_size - 1; ; --j) {
            val += 256 * buf[j];
            buf[j] = (uint8_t)(val % 58);
            val /= 58;

            if (j <= high && val == 0)
                break;

            if (j == 0)
                break;
        }

        /* update highest non-zero digit */
        while (high > 0 && buf[high] == 0)
            high--;
    }

    // Skip leading zero digits
    size_t j = 0;
    while (j < required_size && buf[j] == 0)
        j++;

    size_t enc_len = zcount + (required_size - j);

    if (*out_len <= enc_len) {
        *out_len = enc_len + 1;
        return false;
        if (heap_used) SECURE_FREE(buf, required_size);
    }

    // Leading '1's
    size_t out_i = 0;
    for (; out_i < zcount; ++out_i)
        out[out_i] = BASE58_LEADING_ZERO;

    // Convert digits to characters
    for (; j < required_size; ++j)
        out[out_i++] = BASE58_ENC_TABLE[buf[j]];

    out[out_i] = '\0';
    *out_len = out_i;

    if (heap_used) SECURE_FREE(buf, required_size);
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

    if (data_len == 0) {
        *out_len = 0;
        return true;
    }

    // Count leading '1's → leading zero bytes
    size_t zcount = 0;
    while (zcount < data_len && data[zcount] == BASE58_LEADING_ZERO)
        zcount++;

    // Compute max decoded size
    size_t required_size = BASE58_DEC_LEN(data_len - zcount + 2);

    // No room to decode anything
    if (required_size == 0) {
        if (*out_len < zcount) return false;
        SECURE_ZERO(out, zcount);
        *out_len = zcount;
        return true;
    }

    uint8_t stack_buf[BASE58_MAX_STACK_BUF];
    uint8_t *buf = stack_buf;
    bool heap_used = false;

    if (data_len > BASE58_MAX_STACK_INPUT) {
        buf = malloc(required_size);
        if (!buf) return false;
        heap_used = true;
    }

    SECURE_ZERO(buf, required_size);

    // Base58 -> big integer
    for (size_t i = zcount; i < data_len; ++i) {
        int val = -1;
        unsigned char c = (unsigned char)data[i];

        if (c >= BASE58_MIN && c <= BASE58_MAX)
            val = BASE58_REV_TABLE[c - BASE58_MIN];

        if (val < 0) {
            if (heap_used) SECURE_FREE(buf, required_size);
            return false; // invalid character
        }

        for (size_t j = required_size; j-- > 0; ) {
            val += 58 * buf[j];
            buf[j] = (uint8_t)val;
            val >>= 8;
        }

        // overflow means input doesn't fit in allocated size
        if (val != 0) {
            if (heap_used) SECURE_FREE(buf, required_size);
            return false;
        }
    }

    // Skip leading zeros in big integer
    size_t j = 0;
    while (j < required_size && buf[j] == 0)
        j++;

    size_t decoded_len = zcount + (required_size - j);

    // Output buffer check
    if (*out_len < decoded_len) {
        if (heap_used) SECURE_FREE(buf, required_size);
        return false;
    }

    size_t out_index = 0;

    // Leading zeros from '1's
    for (size_t i = 0; i < zcount; ++i)
        out[out_index++] = 0;

    // Remaining bytes
    for (; j < required_size; ++j)
        out[out_index++] = buf[j];

    *out_len = out_index;

    if (heap_used) SECURE_FREE(buf, required_size);
    return true;
}
