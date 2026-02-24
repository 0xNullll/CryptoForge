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

#include "../../include/cf_api/cf_utils.h"

int CF_Compare(const uint8_t *a, const uint8_t *b, size_t len) {
    if (!a || !b)
        return CF_ERR_NULL_PTR;
        
    if (len == 0)
        return 1;

    // constant-time equality
    return SECURE_MEM_EQUAL(a, b, len) ? 1 : 0;
}

int CF_CompareLex(const uint8_t *a, const uint8_t *b, size_t len) {
    if (!a || !b)
        return CF_ERR_NULL_PTR;
    if (len == 0)
        return CF_ERR_INVALID_LEN;

    // lexicographical comparison
    return SECURE_MEM_CMP_LEX(a, b, len);
}

CF_STATUS CF_EntropyFromOS(uint8_t *buf, size_t len) {
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