#ifndef TCLIB_STATUS_H
#define TCLIB_STATUS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "../config/libs.h"
#include "utils.h"

typedef uint32_t TCLIB_STATUS;

// ==========================
// 1. Global return type
// ==========================
typedef enum {
    // --------------------------
    // General success / failures
    // --------------------------
    TCLIB_SUCCESS = 0,
    TCLIB_ERR_UNKNOWN = 1,

    // --------------------------
    // Argument / input issues
    // --------------------------
    TCLIB_ERR_NULL_PTR,         // Passed NULL pointer
    TCLIB_ERR_INVALID_LEN,      // Invalid length
    TCLIB_ERR_BAD_STATE,        // Wrong call order
    TCLIB_ERR_UNSUPPORTED,      // Unsupported algorithm
    TCLIB_ERR_OUTPUT_TOO_SMALL, // Output buffer too small

    // --------------------------
    // Memory / allocation issues
    // --------------------------
    TCLIB_ERR_ALLOC_FAILED,     // malloc/calloc failed
    TCLIB_ERR_CTX_CORRUPT,      // Context memory corrupted

    // --------------------------
    // Reserved base values for modules
    // --------------------------
    TCLIB_ERR_HASH_BASE   = 0x1000, // Hash-specific errors
    TCLIB_ERR_CIPHER_BASE = 0x2000, // Ciphers (future)
    TCLIB_ERR_MAC_BASE    = 0x3000, // HMAC/KMAC/etc
    TCLIB_ERR_KDF_BASE    = 0x4000, // PBKDF2/Argon/etc
} GLOBAL_TCLIB_STATUS;

// ==========================
// 2. Hash-specific errors
// ==========================
typedef enum {
    TCLIB_ERR_HASH_FINALIZED     = TCLIB_ERR_HASH_BASE, // update after final()
    TCLIB_ERR_HASH_STATE_INVALID,                      // internal state invalid
    TCLIB_ERR_HASH_PAD_ERROR,                          // padding issue (rare)
    TCLIB_ERR_HASH_BAD_BLOCK_SIZE,                     // block misalignment
} HASH_TCLIB_STATUS;

// ==========================
// 3. Status string helper
// ==========================
static FORCE_INLINE const char* tclib_status_str(TCLIB_STATUS status) {
    switch (status) {
        case TCLIB_SUCCESS: return "TCLIB_SUCCESS";
        case TCLIB_ERR_UNKNOWN: return "TCLIB_ERR_UNKNOWN";
        case TCLIB_ERR_NULL_PTR: return "TCLIB_ERR_NULL_PTR";
        case TCLIB_ERR_INVALID_LEN: return "TCLIB_ERR_INVALID_LEN";
        case TCLIB_ERR_BAD_STATE: return "TCLIB_ERR_BAD_STATE";
        case TCLIB_ERR_UNSUPPORTED: return "TCLIB_ERR_UNSUPPORTED";
        case TCLIB_ERR_OUTPUT_TOO_SMALL: return "TCLIB_ERR_OUTPUT_TOO_SMALL";
        case TCLIB_ERR_ALLOC_FAILED: return "TCLIB_ERR_ALLOC_FAILED";
        case TCLIB_ERR_CTX_CORRUPT: return "TCLIB_ERR_CTX_CORRUPT";
        case TCLIB_ERR_HASH_FINALIZED: return "TCLIB_ERR_HASH_FINALIZED";
        case TCLIB_ERR_HASH_STATE_INVALID: return "TCLIB_ERR_HASH_STATE_INVALID";
        case TCLIB_ERR_HASH_PAD_ERROR: return "TCLIB_ERR_HASH_PAD_ERROR";
        case TCLIB_ERR_HASH_BAD_BLOCK_SIZE: return "TCLIB_ERR_HASH_BAD_BLOCK_SIZE";
        default: return "TCLIB_ERR_UNKNOWN";
    }
}

#ifdef __cplusplus
}
#endif

#endif // TCLIB_STATUS_H