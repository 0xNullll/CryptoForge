#ifndef EVP_STATUS_H
#define EVP_STATUS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "../../config/libs.h"
#include "../../utils/utils.h"

typedef uint32_t EVP_STATUS;

// ==========================
// 1. Global EVP return type
// ==========================
typedef enum {
    // --------------------------
    // General success / failures
    // --------------------------
    EVP_OK = 0,
    EVP_ERR_UNKNOWN = 1,

    // --------------------------
    // Argument / input issues
    // --------------------------
    EVP_ERR_NULL_PTR,        // passed NULL pointer
    EVP_ERR_INVALID_LEN,     // invalid length
    EVP_ERR_BAD_STATE,       // wrong call order
    EVP_ERR_UNSUPPORTED,     // unsupported algorithm
    EVP_ERR_OUTPUT_TOO_SMALL,// output buffer too small

    // --------------------------
    // Memory / allocation issues
    // --------------------------
    EVP_ERR_ALLOC_FAILED,    // malloc/calloc failed
    EVP_ERR_CTX_CORRUPT,     // context memory corrupted

    // --------------------------
    // Reserved base values for modules
    // --------------------------
    EVP_ERR_HASH_BASE   = 0x1000,   // hash-specific errors
    EVP_ERR_CIPHER_BASE = 0x2000,   // ciphers (future)
    EVP_ERR_MAC_BASE    = 0x3000,   // HMAC/KMAC/etc
    EVP_ERR_KDF_BASE    = 0x4000,   // PBKDF2/Argon/etc
} EVP_GLOBAL_STATUS;


// ==========================
// 2. Hash-specific errors
// ==========================
typedef enum {
    EVP_ERR_HASH_FINALIZED     = EVP_ERR_HASH_BASE, // update after final()
    EVP_ERR_HASH_STATE_INVALID,                     // internal state invalid
    EVP_ERR_HASH_PAD_ERROR,                         // padding issue (rare)
    EVP_ERR_HASH_BAD_BLOCK_SIZE,                    // block misalignment
} EVP_HASH_STATUS;

static FORCE_INLINE const char* EVP_status_str(EVP_STATUS status) {
    switch (status) {
        case EVP_OK: return "EVP_OK";
        case EVP_ERR_UNKNOWN: return "EVP_ERR_UNKNOWN";
        case EVP_ERR_NULL_PTR: return "EVP_ERR_NULL_PTR";
        case EVP_ERR_INVALID_LEN: return "EVP_ERR_INVALID_LEN";
        case EVP_ERR_BAD_STATE: return "EVP_ERR_BAD_STATE";
        case EVP_ERR_UNSUPPORTED: return "EVP_ERR_UNSUPPORTED";
        case EVP_ERR_OUTPUT_TOO_SMALL: return "EVP_ERR_OUTPUT_TOO_SMALL";
        case EVP_ERR_ALLOC_FAILED: return "EVP_ERR_ALLOC_FAILED";
        case EVP_ERR_CTX_CORRUPT: return "EVP_ERR_CTX_CORRUPT";
        case EVP_ERR_HASH_FINALIZED: return "EVP_ERR_HASH_FINALIZED";
        case EVP_ERR_HASH_STATE_INVALID: return "EVP_ERR_HASH_STATE_INVALID";
        case EVP_ERR_HASH_PAD_ERROR: return "EVP_ERR_HASH_PAD_ERROR";
        case EVP_ERR_HASH_BAD_BLOCK_SIZE: return "EVP_ERR_HASH_BAD_BLOCK_SIZE";
        default: return "EVP_ERR_UNKNOWN";
    }
}

#ifdef __cplusplus
}
#endif

#endif // EVP_STATUS_H