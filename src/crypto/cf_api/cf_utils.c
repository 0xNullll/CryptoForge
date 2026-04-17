/*
 * CryptoForge - cf_utils.c / CryptoForge API Layer Utilities
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

#include <CryptoForge/cf_utils.h>

#include "../../internal/config/libs.h"
#include "../../internal/utils/mem.h"

CF_API int CF_Compare(const uint8_t *a, const uint8_t *b, size_t len) {
    if (!a || !b)
        return CF_ERR_NULL_PTR;
        
    if (len == 0)
        return 1;

    // constant-time equality
    return SECURE_MEM_EQUAL(a, b, len) ? 1 : 0;
}

CF_API int CF_CompareLex(const uint8_t *a, const uint8_t *b, size_t len) {
    if (!a || !b)
        return CF_ERR_NULL_PTR;
    if (len == 0)
        return CF_ERR_INVALID_LEN;

    // lexicographical comparison
    return SECURE_MEM_CMP_LEX(a, b, len);
}

CF_API CF_STATUS CF_EntropyFromOS(uint8_t *buf, size_t len) {
    if (!buf || len == 0)
        return CF_ERR_NULL_PTR;

#if defined(_WIN32)

#if defined(_MSC_VER)
    // Use modern CNG API on MSVC
    if (BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        return CF_ERR_OS_FAIL; // Windows entropy failure
    }
#else
    // Fallback to older CryptoAPI on other Windows compilers
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return CF_ERR_OS_FAIL;
    }
    if (!CryptGenRandom(hProv, (DWORD)len, buf)) {
        CryptReleaseContext(hProv, 0);
        return CF_ERR_OS_FAIL;
    }
    CryptReleaseContext(hProv, 0);
#endif

    return CF_SUCCESS;

#else

#if defined(__linux__)
    // Use getrandom() on modern Linux
    ssize_t ret = getrandom(buf, len, 0);
    if (ret == (ssize_t)len) return CF_SUCCESS;
    if (ret < 0 && errno != ENOSYS) return CF_ERR_OS_FAIL;
#endif

    // fallback to /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return CF_ERR_OS_FAIL;

    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, buf + total, len - total);
        if (n <= 0) { close(fd); return CF_ERR_OS_FAIL; }
        total += (size_t)n;
    }
    close(fd);
    return CF_SUCCESS;

#endif
}

// // not updated
CF_API const char* CF_StatusToStr(CF_STATUS status) {
    switch (status) {
        // --- Generic / common ---
        case CF_SUCCESS: return "CF_SUCCESS";
        case CF_ERR_UNKNOWN: return "CF_ERR_UNKNOWN";
        case CF_ERR_INVALID_PARAM: return "CF_ERR_INVALID_PARAM";
        case CF_ERR_NULL_PTR: return "CF_ERR_NULL_PTR";
        case CF_ERR_INVALID_LEN: return "CF_ERR_INVALID_LEN";
        case CF_ERR_BAD_STATE: return "CF_ERR_BAD_STATE";
        case CF_ERR_UNSUPPORTED: return "CF_ERR_UNSUPPORTED";
        case CF_ERR_OUTPUT_BUFFER_TOO_SMALL: return "CF_ERR_OUTPUT_BUFFER_TOO_SMALL";
        case CF_ERR_LIMIT_EXCEEDED: return "CF_ERR_LIMIT_EXCEEDED";
        case CF_ERR_OVERFLOW: return "CF_ERR_OVERFLOW";
        
        // --- Memory / context ---
        case CF_ERR_ALLOC_FAILED: return "CF_ERR_ALLOC_FAILED";
        case CF_ERR_CTX_CORRUPT: return "CF_ERR_CTX_CORRUPT";
        case CF_ERR_ALREADY_INITIALIZED: return "CF_ERR_ALREADY_INITIALIZED";
        case CF_ERR_CTX_UNINITIALIZED: return "CF_ERR_CTX_UNINITIALIZED";

        // --- Hash errors ---
        case CF_ERR_HASH_FINALIZED: return "CF_ERR_HASH_FINALIZED";
        case CF_ERR_HASH_STATE_INVALID: return "CF_ERR_HASH_STATE_INVALID";

        // --- MAC / HMAC errors ---
        case CF_ERR_MAC_FINALIZED: return "CF_ERR_MAC_FINALIZED";
        case CF_ERR_MAC_VERIFY: return "CF_ERR_MAC_VERIFY";
        case CF_ERR_MAC_INVALID_KEY_LEN: return "CF_ERR_MAC_INVALID_KEY_LEN";
        case CF_ERR_MAC_INVALID_TAG_LEN: return "CF_ERR_MAC_INVALID_TAG_LEN";
        case CF_ERR_MAC_BAD_IV_LEN: return "CF_ERR_MAC_BAD_IV_LEN";

        // --- KDF errors  ---
        case CF_ERR_KDF_ALREADY_EXTRACTED: return "CF_ERR_KDF_ALREADY_EXTRACTED";
        case CF_ERR_KDF_NOT_EXTRACTED_YET: return "CF_ERR_KDF_NOT_EXTRACTED_YET";

        // --- Cipher errors ---
        case CF_ERR_CIPHER_INVALID_KEY_LEN: return "CF_ERR_CIPHER_INVALID_KEY_LEN";
        case CF_ERR_CIPHER_KEY_SETUP: return "CF_ERR_CIPHER_KEY_SETUP";
        case CF_ERR_CIPHER_ENCRYPT: return "CF_ERR_CIPHER_ENCRYPT";
        case CF_ERR_CIPHER_DECRYPT: return "CF_ERR_CIPHER_DECRYPT";
        case CF_ERR_CIPHER_TAG_VERIFY: return "CF_ERR_CIPHER_TAG_VERIFY";
        case CF_ERR_CIPHER_FINALIZED: return "CF_ERR_CIPHER_FINALIZED";

        // --- AEAD Cipher errors ---
        case CF_ERR_AEAD_INVALID_IV: return "CF_ERR_AEAD_INVALID_IV";
        case CF_ERR_AEAD_INVALID_AAD: return "CF_ERR_AEAD_INVALID_AAD";

        // --- Module base errors ---
        case CF_ERR_HASH_BASE_ERROR: return "CF_ERR_HASH_BASE_ERROR";
        case CF_ERR_MAC_BASE_ERROR: return "CF_ERR_MAC_BASE_ERROR";
        case CF_ERR_KDF_BASE_ERROR: return "CF_ERR_KDF_BASE_ERROR";
        case CF_ERR_CIPHER_BASE_ERROR: return "CF_ERR_CIPHER_BASE_ERROR";
        case CF_ERR_AEAD_BASE_ERROR: return "CF_ERR_AEAD_BASE_ERROR";

        default: return "CF_ERR_UNKNOWN";
    }
}