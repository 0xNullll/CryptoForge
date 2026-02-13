/*
 * CryptoForge - crypto_conifig.h / Main Crypto Configuration Header
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against WyChaProof test vectors. No hardware optimizations. Use with caution.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
 */

#ifndef CRYPTO_CONFIG_H
#define CRYPTO_CONFIG_H

#ifndef BUILDING_CF_DLL
#define BUILDING_CF_DLL 1
#endif

// Enable or disable compiler barriers (1 = on, 0 = off)
#ifndef CF_ENABLE_BARRIER
#define CF_ENABLE_BARRIER 0
#endif

// #ifndef CF_DEBUG
// #define CF_DEBUG 1
// #endif

// enable demo/test code (1 = on, 0 = off)
#ifndef ENABLE_TESTS
#define ENABLE_TESTS 1
#endif

// Check every input byte in cf_enc and enforce max length / null termination (1 = on, 0 = off)
#ifndef BASE_TRUNCATE_ON_NULL
#define BASE_TRUNCATE_ON_NULL 0
#endif

#endif // CRYPTO_CONFIG_H