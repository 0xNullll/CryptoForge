/*
 * CryptoForge - mem.c / Secure Memory Utilities (Implementation)
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

#include "mem.h"

// - 'volatile' prevents compiler optimizations that might skip the loop.
void secure_zero(void *ptr, size_t len) {
    if (!ptr || len == 0) return;

    volatile uint8_t *p = (volatile uint8_t*)ptr;
    while (len--) *p++ = 0;
}

#if USE_STRICT_SECURE_MEMORY

void strict_secure_memset(void *dst, const void *src, size_t len) {
    // Level 2/3: OS-backed memory or locked memory copy
}

void strict_secure_memcpy(void *dst, int val, size_t len) {
    // Level 2/3: OS-backed memory or locked memory copy
}

#else

// - Works like memset but guaranteed not to be optimized away.
// - 'volatile' ensures the writes happen even if the compiler thinks they are unnecessary.
void secure_memset(void *dst, int val, size_t len) {
    if (!dst || len == 0) return;
    volatile uint8_t *p = (volatile uint8_t *)dst;
    while (len--) *p++ = (uint8_t)val;
}

#endif // USE_STRICT_SECURE_MEMORY

// - Ensures sensitive data does not remain in memory after free.
// - 'volatile' prevents compiler optimizations.
void secure_free(void *ptr, size_t size) {
    if (!ptr) return;

    volatile uint8_t *p = (volatile uint8_t*)ptr;
    while (size--) *p++ = 0;

    free(ptr);
    ptr = NULL;
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