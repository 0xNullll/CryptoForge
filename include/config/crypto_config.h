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

#ifndef CF_DEBUG
#define CF_DEBUG 1
#endif

#ifndef ENABLE_TESTS
#define ENABLE_TESTS 1       // enable demo/test code
#endif

#ifndef BASE_TRUNCATE_ON_NULL
#define BASE_TRUNCATE_ON_NULL 0 // Check every input byte and enforce max length / null termination
#endif

#endif // CRYPTO_CONFIG_H