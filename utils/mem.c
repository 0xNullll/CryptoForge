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