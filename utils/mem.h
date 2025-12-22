/*
 * CryptoForge - mem.h / Secure Memory Utilities (Header)
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

#ifndef MEM_H
#define MEM_H

/**
 * Memory Management Layers
 *
 * This library provides **three optional memory management layers** to handle
 * different use cases, security levels, and performance requirements:
 *
 * 1. **Secure, non-OS-based memory**  
 *    - Direct memory operations without relying on OS primitives.  
 *    - Ensures secure zeroing, custom allocation, and no hidden system calls.  
 *    - Useful for deterministic low-level memory handling and high-security contexts.
 *
 * 2. **OS-based memory without locks**  
 *    - Uses OS allocation primitives (e.g., VirtualAlloc / mmap / malloc).  
 *    - No internal locking; suitable for single-threaded or carefully synchronized code.  
 *    - Lightweight and faster than locked versions.
 *
 * 3. **OS-based memory with locks**  
 *    - Thread-safe allocations using locks/mutexes.  
 *    - Ensures correctness in multi-threaded environments.  
 *    - Slightly higher overhead but safe for concurrent access.
 *
 * Combined with the **optional per-file memory tracking**, these layers allow:
 * - Fine-grained control over security and performance.  
 * - Accurate debugging and profiling in constrained environments.  
 * - Flexible selection depending on the target system and use case.
 *
 * Note:
 * Most crypto libraries do not provide multiple configurable memory layers with
 * built-in tracking; this design aims to give full control and observability
 * without sacrificing performance.
 */

#include "../config/libs.h"
#include "misc_utils.h"

// -----------------------------------------------------------------------------
// Level 1: Normal secure memory functions
// -----------------------------------------------------------------------------

// Allocate memory safely and zero-initialize
static FORCE_INLINE void* secure_malloc(size_t size) {
    if (size == 0) return NULL;
    void *ptr = calloc(1, size);
    return ptr;
}

// Overwrite a memory block with zeros without freeing
void secure_zero(void *ptr, size_t len);

#if USE_STRICT_SECURE_MEMORY

// Placeholders for future Level 2 / 3 implementations
void strict_secure_memset(void *dst, int val, size_t len);
void strict_secure_memcpy(void *dst, const void *src, size_t len);

#else

// Safe memory copy with null-pointer and length checks
static FORCE_INLINE void secure_memcpy(void *dst, const void *src, size_t len) {
    if (!dst || !src || len == 0) return;
    memcpy(dst, src, len);
}

// Overwrite memory safely, preventing compiler optimizations
void secure_memset(void *dst, int val, size_t len);

#endif // USE_STRICT_SECURE_MEMORY

// Secure free: zero memory before freeing
void secure_free(void *ptr, size_t size);

/**
 * @brief Constant-time memory equality check
 * 
 * Compares two memory buffers of length `len` in constant time.
 * Returns 1 if equal, 0 if not equal, or CF_ERR_* on invalid input.
 * 
 * @param a Pointer to first buffer
 * @param b Pointer to second buffer
 * @param len Length of buffers in bytes
 * @return int 1 if equal, 0 if unequal, CF_ERR_NULL_PTR or CF_ERR_INVALID_LEN
 */
int secure_mem_equal(const uint8_t *a, const uint8_t *b, size_t len);

/**
 * @brief Constant-time lexicographical comparison
 * 
 * Compares two memory buffers in lexicographical order without branching on secret data.
 * Returns:
 *   -  1 if a > b
 *   -  0 if a == b
 *   - -1 if a < b
 *   - CF_ERR_NULL_PTR or CF_ERR_INVALID_LEN on invalid input
 * 
 * @param a Pointer to first buffer
 * @param b Pointer to second buffer
 * @param len Length of buffers in bytes
 * @return int Comparison result
 */
int secure_mem_compare_lex(const uint8_t *a, const uint8_t *b, size_t len);

// -----------------------------------------------------------------------------
// Convenience macros
// -----------------------------------------------------------------------------
#define SECURE_ALLOC(sz)        secure_malloc((sz))
#define SECURE_ZERO(buf, len)   secure_zero((buf), (len))

#if USE_STRICT_SECURE_MEMORY
  #define SECURE_MEMSET(dst, val, len) strict_secure_memset((dst), (val), (len))
  #define SECURE_MEMCPY(dst, src, len) strict_secure_memcpy((dst), (src), (len))
#else
  #define SECURE_MEMSET(dst, val, len) secure_memset((dst), (val), (len))
  #define SECURE_MEMCPY(dst, src, len) secure_memcpy((dst), (src), (len))
#endif

#define SECURE_FREE(ptr, size)  secure_free((ptr), (size))

#define SECURE_MEM_EQUAL(a, b, len)     (secure_mem_equal((a), (b), (len)) == 1)
#define SECURE_MEM_CMP_LEX(a, b, len)   (secure_mem_compare_lex((a), (b), (len)))

#endif // MEM_H