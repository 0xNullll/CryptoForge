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

    // Count leading zeros
    size_t zeros = 0;
    while (zeros < data_len && data[zeros] == 0) zeros++;

    if (zeros == data_len) {
        // All-zero input
        if (*out_len < zeros + 1) {
            *out_len = zeros + 1;
            return false;
        }
        for (size_t i = 0; i < zeros; i++) out[i] = BASE58_LEADING_ZERO;
        out[zeros] = '\0';
        *out_len = zeros;
        return true;
    }

    size_t size = BASE58_ENC_LEN(data_len);
    uint8_t stack_buf[BASE58_MAX_STACK_BUF] = {0};
    uint8_t *buf = stack_buf;
    bool heap_used = false;

    if (data_len > BASE58_MAX_STACK_INPUT) {
        buf = SECURE_ALLOC(size);
        SECURE_ZERO(buf, size);
        if (!buf) return false;
        heap_used = true;
    }

    // Process input bytes
    for (size_t i = zeros; i < data_len; i++) {
        uint32_t carry = data[i];
        for (int64_t j = (int64_t)size - 1; j >= 0; j--) {
            carry += 256u * buf[j];
            buf[j] = (uint8_t)(carry % 58);
            carry /= 58;
        }
        // If carry != 0 here, size was too small (should not happen with base58_enc_len)
    }

    // Skip leading zeros in buf
    size_t j = 0;
    while (j < size && buf[j] == 0) j++;

    size_t enc_len = zeros + (size - j);
    if (*out_len <= enc_len) {
        *out_len = enc_len + 1;
        if (heap_used) SECURE_FREE(buf, size);
        return false;
    }

    // Leading '1's
    size_t out_i = 0;
    for (; out_i < zeros; out_i++) out[out_i] = BASE58_LEADING_ZERO;

    // Convert digits to characters
    for (; j < size; j++) out[out_i++] = BASE58_ENC_TABLE[buf[j]];

    out[out_i] = '\0';
    *out_len = out_i;

    if (heap_used) SECURE_FREE(buf, size);
    return true;
}

bool ll_BASE58_Decode(const char *data, size_t data_len, uint8_t *out, size_t *out_len) {
    if (!data || data_len == 0 || !out || !out_len) return false;

#if BASE_TRUNCATE_ON_NULL
    for (size_t i = 0; i < data_len; ++i) {
        if (data[i] == '\0') {
            data_len = i;
            break;
        }
    }
#endif

    // Count leading '1's → leading zeros
    size_t zcount = 0;
    while (zcount < data_len && data[zcount] == BASE58_LEADING_ZERO)
        zcount++;

    size_t max_dec = BASE58_DEC_LEN(data_len - zcount + 2);
    uint8_t stack_buf[BASE58_MAX_STACK_BUF] = {0};
    uint8_t *buf = stack_buf;
    bool heap_used = false;

    if (data_len > BASE58_MAX_STACK_INPUT) {
        buf = SECURE_ALLOC(max_dec);
        if (!buf) return false;
        heap_used = true;
        SECURE_ZERO(buf, max_dec);
    }

    // Base58 -> big integer in bytes
    for (size_t i = zcount; i < data_len; ++i) {
        int8_t  rev = BASE58_REV_TABLE[(uint8_t)data[i] - BASE58_MIN];
        if (rev < 0) {
            if (heap_used) SECURE_FREE(buf, max_dec);
            return false;
        }

        uint32_t carry = (uint32_t)rev;
        for (int64_t j = (int64_t)max_dec - 1; j >= 0; --j) {
            carry += 58u * buf[j];
            buf[j] = carry & 0xFF;
            carry >>= 8;
        }

        if (carry != 0) {
            if (heap_used) SECURE_FREE(buf, max_dec);
            return false;
        }
    }

    // Skip leading zeros in buffer
    size_t j = 0;
    while (j < max_dec && buf[j] == 0) j++;

    size_t decoded_len = zcount + (max_dec - j);
    if (*out_len < decoded_len) {
        if (heap_used) SECURE_FREE(buf, max_dec);
        return false;
    }

    size_t out_i = 0;
    for (size_t k = 0; k < zcount; ++k)
        out[out_i++] = 0;
    for (; j < max_dec; ++j)
        out[out_i++] = buf[j];

    *out_len = out_i;
    if (heap_used) SECURE_FREE(buf, max_dec);
    return true;
}