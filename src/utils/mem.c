/*
 * CryptoForge - mem.c / Secure Memory Utilities Implementation
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "../internal/utils/mem.h"

#if ENABLE_BARRIER
//
// Compiler-specific memory barrier
//

// GCC / Clang: use an empty volatile asm block
// This tells the compiler that memory pointed to by 'ptr' of length 'len'
// may be read/written, preventing it from reordering or optimizing away
// memory operations around this point.
#if defined(__GNUC__) || defined(__clang__)
    #define CF_MEM_BARRIER(ptr, len) \
        __asm__ volatile("" : : "m" (*(volatile char (*)[len]) (ptr)) : "memory")

// MSVC: use intrinsic _ReadWriteBarrier()
// This prevents the compiler from moving memory operations across this barrier
#elif defined(_MSC_VER)
    #define CF_MEM_BARRIER(ptr, len) _ReadWriteBarrier()

// Fallback: do nothing but silence unused variable warnings
// If the compiler/platform is unknown, we can't enforce a barrier
// but this keeps code compilable.
#else
    #define CF_MEM_BARRIER(ptr, len) do { (void)(ptr); (void)(len); } while(0)
#endif

#endif // ENABLE_BARRIER

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
    size_t tmp_len = len;  // store original length for barrier
    while (tmp_len--) *p++ = 0;

    // Compiler barrier: pretend memory was read
#if ENABLE_BARRIER
    // use original len, not decremented tmp_len
    CF_MEM_BARRIER(buf, len);
#endif // ENABLE_BARRIER
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
        size_t tmp_len = len;  // store original length for barrier
        while (tmp_len--) *p++ = (unsigned char)val;

#if ENABLE_BARRIER
    // compiler barrier to prevent reordering/elimination
    CF_MEM_BARRIER(dst, len);
#endif // ENABLE_BARRIER
    }
}

void secure_memcpy(void *dst, const void *src, size_t len) {
    if (!dst || !src || len == 0) return;

    // Use standard memcpy since copy itself is not secret-sensitive,
    // but can optionally combine with compiler barrier if paranoid
    memcpy(dst, src, len);

#if ENABLE_BARRIER
    // compiler barrier to prevent reordering/elimination
    CF_MEM_BARRIER(dst, len);
#endif
}

int secure_mem_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    if (!a || !b) return 0;
    if (len == 0) return 1;

    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }

#if defined(__GNUC__) || defined(__clang__)
    // force compiler to see diff as “used” memory
    __asm__ volatile("" : "+r"(diff) : : "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#else
    (void)diff;
#endif

    return diff == 0;
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

#if defined(__GNUC__) || defined(__clang__)
    // force compiler to see diff as “used” memory
    __asm__ volatile("" : : "r"(lt), "r"(gt), "r"(seen) : "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#endif

    return (int)gt - (int)lt;
}