/*
 * CryptoForge - cf_status.h / Global Status Codes and Helpers
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CF_STATUS_H
#define CF_STATUS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef uint32_t CF_STATUS;

typedef enum {
    CF_SUCCESS = 0,
    CF_ERR_UNKNOWN = 1,

    //
    // Argument / input issues
    //
    CF_ERR_INVALID_PARAM,           // generic “invalid argument” code
    CF_ERR_NULL_PTR,                // Passed NULL pointer
    CF_ERR_INVALID_LEN,             // Invalid length
    CF_ERR_BAD_STATE,               // Wrong call order
    CF_ERR_OS_FAIL,                 // generic OS error  
    CF_ERR_UNSUPPORTED,             // Unsupported algorithm
    CF_ERR_OUTPUT_BUFFER_TOO_SMALL, // Output buffer too small
    CF_ERR_LIMIT_EXCEEDED,          // generic max/limit error
    CF_ERR_OVERFLOW,                // generic overflow error
     
    //
    // Memory / allocation issues
    //
    CF_ERR_ALLOC_FAILED,            // malloc/calloc failed
    CF_ERR_CTX_CORRUPT,             // Context memory corrupted
    CF_ERR_ALREADY_INITIALIZED,     // Context initialized memory
    CF_ERR_CTX_UNINITIALIZED,       // Context uninitialized memory
    CF_ERR_CTX_OPTS_UNINITIALIZED,  // Context optional uninitialized memory

    //
    // Reserved base values for modules
    //
    CF_ERR_HASH_BASE   = 0x1000, // Hash-specific errors
    CF_ERR_MAC_BASE    = 0x2000, // HMAC/KMAC/etc
    CF_ERR_KDF_BASE    = 0x3000, // PBKDF2/Argon/etc
    CF_ERR_CIPHER_BASE = 0x4000, // Ciphers
    CF_ERR_AEAD_BASE   = 0x5000 // AEAD Ciphers
} GLOBAL_CF_STATUS;

//
// 2. Hash-specific errors
//
typedef enum {
    CF_ERR_HASH_BASE_ERROR     = CF_ERR_HASH_BASE,  // base for hash errors
    CF_ERR_HASH_FINALIZED,                          // update after final()
    CF_ERR_HASH_STATE_INVALID,                      // internal state invalid
} HASH_CF_STATUS;

//
// 3. MAC errors
//
typedef enum {
    CF_ERR_MAC_BASE_ERROR      = CF_ERR_MAC_BASE,    // base for MAC errors
    CF_ERR_MAC_FINALIZED,                            // update after final()
    CF_ERR_MAC_VERIFY,                               // HMAC verification failed
    CF_ERR_MAC_INVALID_KEY_LEN,                      // poly1305 key length is invalid
    CF_ERR_MAC_INVALID_TAG_LEN,                      // tag length is incorrect and unsafe
    CF_ERR_MAC_BAD_IV_LEN,                           // iv length is not recommended and unsafe
} MAC_CF_STATUS;

//
// 4. KDF errors
//
typedef enum {
    CF_ERR_KDF_BASE_ERROR      = CF_ERR_KDF_BASE,    // base for KDF errors
    CF_ERR_KDF_ALREADY_EXTRACTED,                    // calling the Extract() again
    CF_ERR_KDF_NOT_EXTRACTED_YET                     // calling the Expand() before Extract()
} KDF_CF_STATUS;

//
// 5. Cipher errors
//
typedef enum {
    CF_ERR_CIPHER_BASE_ERROR   = CF_ERR_CIPHER_BASE,    // base for ciphers errors
    CF_ERR_CIPHER_INVALID_KEY_LEN,                      // invalid key length
    CF_ERR_CIPHER_KEY_SETUP,                            // error during key setup
    CF_ERR_CIPHER_ENCRYPT,                              // encryption failed
    CF_ERR_CIPHER_DECRYPT,                              // decryption failed
    CF_ERR_CIPHER_TAG_VERIFY,                           // GCM/GMAC tag verification failed
    CF_ERR_CIPHER_FINALIZED,                            // update called after finalize
} CIPHER_CF_STATUS;

//
// 6. AEAD Cipher errors
//
typedef enum {
    CF_ERR_AEAD_BASE_ERROR   = CF_ERR_AEAD_BASE,    // base for AEAD ciphers errors
    CF_ERR_AEAD_INVALID_IV,                         // AEAD nonce/IV too short/long
    CF_ERR_AEAD_INVALID_AAD,                        // AEAD AAD exceeding limits
} AEAD_CF_STATUS;

#ifdef __cplusplus
}
#endif

#endif // CF_STATUS_H