/*
 * CryptoForge - cf_status.h / Global Status Codes and Helpers
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

#ifndef CF_STATUS_H
#define CF_STATUS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "../config/libs.h"
#include "misc_utils.h"

typedef uint32_t CF_STATUS;

// ==========================
// 1. Global return type
// ==========================
typedef enum {
    // --------------------------
    // General success / failures
    // --------------------------
    CF_SUCCESS = 0,
    CF_ERR_UNKNOWN = 1,
    // --------------------------
    // Argument / input issues
    // --------------------------
    CF_ERR_INVALID_PARAM,           // generic “invalid argument” code
    CF_ERR_NULL_PTR,                // Passed NULL pointer
    CF_ERR_INVALID_LEN,             // Invalid length
    CF_ERR_BAD_STATE,               // Wrong call order
    CF_ERR_UNSUPPORTED,             // Unsupported algorithm
    CF_ERR_OUTPUT_BUFFER_TOO_SMALL, // Output buffer too small
    CF_ERR_LIMIT_EXCEEDED,

    // --------------------------
    // Memory / allocation issues
    // --------------------------
    CF_ERR_ALLOC_FAILED,     // malloc/calloc failed
    CF_ERR_CTX_CORRUPT,      // Context memory corrupted

    // --------------------------
    // Reserved base values for modules
    // --------------------------
    CF_ERR_HASH_BASE   = 0x1000, // Hash-specific errors
    CF_ERR_CIPHER_BASE = 0x2000, // Ciphers
    CF_ERR_MAC_BASE    = 0x3000, // HMAC/KMAC/etc
    CF_ERR_KDF_BASE    = 0x4000, // PBKDF2/Argon/etc
} GLOBAL_CF_STATUS;

// ==========================
// 2. Hash-specific errors
// ==========================
typedef enum {
    CF_ERR_HASH_FINALIZED     = CF_ERR_HASH_BASE,   // update after final()
    CF_ERR_HASH_STATE_INVALID,                      // internal state invalid
    CF_ERR_HASH_PAD_ERROR,                          // padding issue (rare)
    CF_ERR_HASH_BAD_BLOCK_SIZE,                     // block misalignment
} HASH_CF_STATUS;

// ==========================
// 3. MAC/HMAC-specific errors
// ==========================
typedef enum {
    CF_ERR_MAC_BASE_ERROR      = CF_ERR_MAC_BASE,   // base for MAC errors
    CF_ERR_MAC_VERIFY,                               // HMAC verification failed
    CF_ERR_MAC_STATE_INVALID,                        // internal context/state invalid
} MAC_CF_STATUS;

// ==========================
// 4. Cipher/GCM/GMAC-specific errors
// ==========================
typedef enum {
    CF_ERR_CIPHER_BASE_ERROR   = CF_ERR_CIPHER_BASE,    // base for ciphers errors
    CF_ERR_CIPHER_KEY_SETUP,                            // error during key setup
    CF_ERR_CIPHER_ENCRYPT,                              // encryption failed
    CF_ERR_CIPHER_DECRYPT,                              // decryption failed
    CF_ERR_CIPHER_STATE_INVALID,                        // internal state invalid
    CF_ERR_CIPHER_TAG_VERIFY,                           // GCM/GMAC tag verification failed
    CF_ERR_CIPHER_FINALIZED,                            // update called after finalize
} CIPHER_CF_STATUS;

static FORCE_INLINE const char* CF_status_str(CF_STATUS status) {
    switch (status) {
        case CF_SUCCESS: return "CF_SUCCESS";
        case CF_ERR_UNKNOWN: return "CF_ERR_UNKNOWN";
        case CF_ERR_NULL_PTR: return "CF_ERR_NULL_PTR";
        case CF_ERR_INVALID_LEN: return "CF_ERR_INVALID_LEN";
        case CF_ERR_BAD_STATE: return "CF_ERR_BAD_STATE";
        case CF_ERR_UNSUPPORTED: return "CF_ERR_UNSUPPORTED";
        case CF_ERR_OUTPUT_BUFFER_TOO_SMALL: return "CF_ERR_OUTPUT_BUFFER_TOO_SMALL";
        case CF_ERR_LIMIT_EXCEEDED: return "CF_ERR_LIMIT_EXCEEDED";
        case CF_ERR_ALLOC_FAILED: return "CF_ERR_ALLOC_FAILED";
        case CF_ERR_CTX_CORRUPT: return "CF_ERR_CTX_CORRUPT";
        case CF_ERR_HASH_FINALIZED: return "CF_ERR_HASH_FINALIZED";
        case CF_ERR_HASH_STATE_INVALID: return "CF_ERR_HASH_STATE_INVALID";
        case CF_ERR_HASH_PAD_ERROR: return "CF_ERR_HASH_PAD_ERROR";
        case CF_ERR_HASH_BAD_BLOCK_SIZE: return "CF_ERR_HASH_BAD_BLOCK_SIZE";
        default: return "CF_ERR_UNKNOWN";
    }
}

#ifdef __cplusplus
}
#endif

#endif // CF_STATUS_H