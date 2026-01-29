/*
 * CryptoForge - crypto_conifig.h / Main Crypto Configuration Header
 * Copyright (C) 2025 0xNullll
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License in the file LICENSE in the
 * source distribution or at:
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * This software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
 * OR CONDITIONS OF ANY KIND, either express or implied. See the License
 * for the specific language governing permissions and limitations under
 * the License.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#ifndef CRYPTO_CONFIG_H
#define CRYPTO_CONFIG_H

#ifndef BUILDING_CF_DLL
#define BUILDING_CF_DLL 1
#endif

#ifndef USE_STRICT_SECURE_MEMORY
#define USE_STRICT_SECURE_MEMORY 0  // enable OS based memory functions for maximum security and prevent advanced side-channel attacks
#endif

#ifndef ENABLE_TESTS
#define ENABLE_TESTS 1       // enable demo/test code
#endif

#ifndef BASE_TRUNCATE_ON_NULL
#define BASE_TRUNCATE_ON_NULL 0 // Check every input byte and enforce max length / null termination
#endif

// ------------------------
// Function name prefix support
// ------------------------
#ifndef TSHASH_PREFIX
#define TSHASH_PREFIX
#endif

#define _TS_CAT(a,b) a##b
#define _TS_CAT2(a,b) _TS_CAT(a,b)
#define TC_TSHASH_FN(name) _TS_CAT2(TSHASH_PREFIX, name)

// ------------------------
// Endianness detection
// ------------------------
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define CPU_BIG_ENDIAN 1
#elif defined(_BIG_ENDIAN) || defined(__BIG_ENDIAN__) || defined(__ARMEB__) || defined(__MIPSEB__)
#define CPU_BIG_ENDIAN 1
#else
#define CPU_BIG_ENDIAN 0
#endif

#endif // CRYPTO_CONFIG_H