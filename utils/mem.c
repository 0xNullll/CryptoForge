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