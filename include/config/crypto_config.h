/*
 * CryptoForge - crypto_conifig.h / Main Crypto Configuration Header
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