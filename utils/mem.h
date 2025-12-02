#ifndef MEM_H
#define MEM_H

/**
 * @file mem.h
 * @brief Secure memory management functions for CryptoForge
 *
 * This header provides **level-one secure memory functions**:
 * 1. Allocation with zero-initialization (using calloc)
 * 2. Memory copy and zeroing with volatile to prevent compiler optimizations
 * 3. Secure free (zero memory before freeing)
 *
 * Future expansion (Level 2 & 3):
 * - OS-backed memory allocation and locking
 * - Advanced secure zeroing and constant-time copy
 *
 * Macros provide a unified interface: SECURE_ALLOC, SECURE_MEMSET, SECURE_MEMCPY, SECURE_FREE
 */

/**
 * Memory Tracking (Optional Debugging)
 *
 * This feature allows tracking memory usage **per source file**. It is intended
 * for debugging, profiling, and planning memory requirements in constrained
 * environments (embedded devices, VMs, or limited RAM systems).
 *
 * Features:
 * - Tracks total memory allocated per file.
 * - Optional logging of allocations with file and line information for advanced debugging.
 * - Can help detect memory leaks, excessive allocations, or heavy memory usage per module.
 * - Disabled in release builds for zero overhead.
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

#endif // MEM_H