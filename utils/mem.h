/*
 * CryptoForge - mem.h / Secure Memory Utilities (Header)
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

#ifndef MEM_H
#define MEM_H

/**
 * Secure Memory Utilities
 *
 * This library provides **secure memory management functions** designed
 * for cryptographic applications and sensitive data handling.
 *
 * Features:
 * - **Secure memory operations**: Zeroing, freeing, copying, and setting memory
 *   in a way that prevents compiler optimizations from skipping critical security operations.
 * - **Constant-time memory comparisons**: Prevents timing attacks by avoiding branching
 *   on secret data.
 * - **Convenience macros**: Simplifies allocation, zeroing, copying, and freeing
 *   while maintaining security guarantees.
 *
 * Goals:
 * - Provide **full control** over memory operations for security-sensitive contexts.
 * - Enable **portable, compiler-safe secure memory handling** across platforms.
 */

#include "../config/libs.h"
#include "misc_utils.h"


/**
 * @brief Allocate memory safely and zero-initialize it.
 *
 * @param size Number of bytes to allocate
 * @return Pointer to allocated memory, or NULL if size is 0
 */
static FORCE_INLINE void* secure_malloc(size_t size) {
    if (size == 0) return NULL;
    void *ptr = calloc(1, size);
    return ptr;
}

/**
 * @brief Overwrite a memory block with zeros without freeing it.
 *
 * @param ptr Pointer to memory block
 * @param len Length of memory block in bytes
 */
void secure_zero(void *ptr, size_t len);

/**
 * @brief Safe memory copy with null-pointer and length checks.
 *
 * @param dst Destination buffer
 * @param src Source buffer
 * @param len Number of bytes to copy
 */
void secure_memcpy(void *dst, const void *src, size_t len);

/**
 * @brief Overwrite memory safely with a given value, preventing compiler optimizations.
 *
 * @param dst Destination buffer
 * @param val Value to write
 * @param len Number of bytes to write
 */
void secure_memset(void *dst, int val, size_t len);

/**
 * @brief Secure free: zero memory before freeing.
 *
 * @param ptr Pointer to memory block
 * @param size Size of memory block in bytes
 */
void secure_free(void *ptr, size_t size);

/**
 * @brief Constant-time memory equality check
 *
 * @param a Pointer to first buffer
 * @param b Pointer to second buffer
 * @param len Length of buffers in bytes
 * @return 1 if equal, 0 if unequal
 */
int secure_mem_equal(const uint8_t *a, const uint8_t *b, size_t len);

/**
 * @brief Constant-time lexicographical comparison
 *
 * @param a Pointer to first buffer
 * @param b Pointer to second buffer
 * @param len Length of buffers in bytes
 * @return  1 if a > b, 0 if a == b, -1 if a < b
 */
int secure_mem_compare_lex(const uint8_t *a, const uint8_t *b, size_t len);

// -----------------------------------------------------------------------------
// Convenience macros
// -----------------------------------------------------------------------------
#define SECURE_ALLOC(sz)        secure_malloc((sz))
#define SECURE_ZERO(buf, len)   secure_zero((buf), (len))

#define SECURE_MEMSET(dst, val, len) secure_memset((dst), (val), (len))
#define SECURE_MEMCPY(dst, src, len) secure_memcpy((dst), (src), (len))

#define SECURE_FREE(ptr, size)  secure_free((ptr), (size))

#define SECURE_MEM_EQUAL(a, b, len)     (secure_mem_equal((a), (b), (len)) == 1)
#define SECURE_MEM_CMP_LEX(a, b, len)   (secure_mem_compare_lex((a), (b), (len)))

#endif // MEM_H