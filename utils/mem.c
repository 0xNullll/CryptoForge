/*
 * CryptoForge - mem.c / Secure Memory Utilities (Implementation)
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

#include "../include/utils/mem.h"

void secure_zero(void *buf, size_t len) {
    if (!buf || len == 0) return;

#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25))
    // Linux glibc >= 2.25
    explicit_bzero(buf, len);

#elif defined(__STDC_LIB_EXT1__) && !defined(__IAR_SYSTEMS_ICC__)
    // C11 secure memset
    memset_s(buf, len, 0, len);

#elif defined(_WIN32)
    // Windows
    SecureZeroMemory(buf, len);

#else
    // Fallback: volatile pointer to prevent compiler optimization
    volatile unsigned char *p = (volatile unsigned char *)buf;
    while (len--) *p++ = 0;

    // Compiler barrier: pretend memory was read
#if defined(__GNUC__) || defined(__clang__)
    asm volatile ("" : : "m" (*(char (*)[len]) buf) : "memory");
#endif
#endif
}

void secure_free(void *ptr, size_t size) {
    if (!ptr || size == 0) return;

    // Securely zero memory first
    secure_zero(ptr, size);

    // Free memory
    free(ptr);
    ptr = NULL; // has no effect outside the function but doesn't hurt :)
}

void secure_memset(void *dst, int val, size_t len) {
    if (!dst || len == 0) return;

    // For val == 0, use platform-optimized secure zeroing
    if (val == 0) {
        secure_zero(dst, len);
    } else {
        // Non-zero value — fallback to volatile write loop
        volatile unsigned char *p = (volatile unsigned char*)dst;
        while (len--) *p++ = (unsigned char)val;

    #if defined(__GNUC__) || defined(__clang__)
        asm volatile ("" : : "m" (*(char (*)[len]) dst) : "memory");
    #endif
    }
}

void secure_memcpy(void *dst, const void *src, size_t len) {
    if (!dst || !src || len == 0) return;

    // Use standard memcpy since copy itself is not secret-sensitive,
    // but can optionally combine with compiler barrier if paranoid
    memcpy(dst, src, len);

#if defined(__GNUC__) || defined(__clang__)
    asm volatile ("" : : "r,m"(dst), "r,m"(src) : "memory");
#endif
}

int secure_mem_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    if (!a || !b) return 0;
    if (len == 0) return 0;

    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= a[i] ^ b[i];
    }

    // return 1 if equal, 0 if not equal
    return (diff == 0);
}

int secure_mem_compare_lex(const uint8_t *a, const uint8_t *b, size_t len) {
    if (!a || !b) return 0;
    if (len == 0) return 0;

    uint32_t lt = 0;
    uint32_t gt = 0;
    uint32_t seen = 0;

    for (size_t i = 0; i < len; ++i) {
        uint16_t ai = (uint16_t)a[i];
        uint16_t bi = (uint16_t)b[i];

        uint16_t d1 = (uint16_t)(ai - bi);  // top bit set if ai < bi
        uint16_t d2 = (uint16_t)(bi - ai);  // top bit set if bi < ai

        uint32_t is_lt = (uint32_t)(d1 >> 15); // 1 if ai < bi
        uint32_t is_gt = (uint32_t)(d2 >> 15); // 1 if ai > bi

        uint32_t diff = is_lt | is_gt;             // 1 if bytes differ
        uint32_t new_diff_mask = (~seen) & diff;   // first differing byte only

        lt |= is_lt & new_diff_mask;
        gt |= is_gt & new_diff_mask;

        seen |= diff;
    }

    return (int)gt - (int)lt;
}