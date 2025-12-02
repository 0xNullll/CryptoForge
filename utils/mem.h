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