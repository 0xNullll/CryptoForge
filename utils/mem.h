#ifndef MEM_H
#define MEM_H

#include "../config/libs.h"
#include "misc_utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// -------------------------
// Secure memory allocation
// -------------------------
static FORCE_INLINE void* secure_malloc(size_t size) {
    if (size == 0) return NULL;

    // calloc guarantees zero-initialized memory
    void *ptr = calloc(1, size);
    return ptr;
}

// Secure free without double pointer
static FORCE_INLINE void secure_free(void *ptr, size_t size) {
    if (!ptr) return;

    volatile uint8_t *p = (volatile uint8_t*)ptr;
    while (size--) *p++ = 0;

    free(ptr);
    ptr = NULL;
}

// Zero memory without freeing
static FORCE_INLINE void secure_zero(void *ptr, size_t len) {
    if (!ptr || len == 0) return;

    volatile uint8_t *p = (volatile uint8_t*)ptr;
    while (len--) *p++ = 0;
}

// checks for null pointers
static FORCE_INLINE void secure_memcpy(void *dst, const void *src, size_t len) {
    if (!dst || !src || len == 0) return;
    memcpy(dst, src, len);
}

// Secure memset: guaranteed not to be optimized away
static FORCE_INLINE void secure_memset(void *dst, int val, size_t len) {
    if (!dst || len == 0) return;
    volatile uint8_t *p = (volatile uint8_t *)dst;
    while (len--) *p++ = (uint8_t)val;
}

// -------------------------
// Context helpers
// -------------------------
static FORCE_INLINE void* create_ctx(size_t ctx_size) {
    return secure_malloc(ctx_size);
}

// Destroy context (just free memory, cannot nullify caller)
static FORCE_INLINE void destroy_ctx(void *ctx, size_t ctx_size) {
    if (!ctx) return;
    secure_free(ctx, ctx_size);
}

// -------------------------
// Macros for convenience
// -------------------------
#define SECURE_ALLOC(sz)        secure_malloc((sz))
#define SECURE_ZERO(buf, len)   secure_zero((buf), (len))
#define SECURE_FREE(ptr, size)  secure_free((ptr), (size))

#define SECURE_MEMCPY(dst, src, len) secure_memcpy((dst), (src), (len))
#define SECURE_MEMSET(dst, val, len) secure_memset((dst), (val), (len))

// Safely clear a fixed-size buffer (array)
#define CLEAR_BUF(buf)           secure_zero((buf), sizeof(buf))

// Context helpers
#define CREATE_CTX(type)        ((type*)create_ctx(sizeof(type)))
#define DESTROY_CTX(ptr, type)  destroy_ctx((ptr), sizeof(type))

#endif // MEM_H