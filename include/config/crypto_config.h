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