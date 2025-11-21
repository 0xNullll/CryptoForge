#ifndef MEM_UTILS_H
#define MEM_UTILS_H

#include "../config/libs.h"
#include "utils.h"

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

// Safely clear a fixed-size buffer (array)
#define CLEAR_BUF(buf)          secure_zero((buf), sizeof(buf))

#define CREATE_CTX(type)        ( (type*)create_ctx(sizeof(type)) )
#define DESTROY_CTX(ptr, type)  destroy_ctx((ptr), sizeof(type))

#endif // MEM_UTILS_H
