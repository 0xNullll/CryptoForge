/*
 * CryptoForge - crypto_conifig.h / Main Crypto Configuration Header
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
#ifndef CRYPTO_CONFIG_H
#define CRYPTO_CONFIG_H

#ifndef BUILDING_CF_DLL
#define BUILDING_CF_DLL 1
#endif

// Enable or disable compiler barriers (1 = on, 0 = off)
#ifndef CF_ENABLE_BARRIER
#define CF_ENABLE_BARRIER 0
#endif

#ifndef CF_DEBUG
#define CF_DEBUG 0
#endif

// enable demo/test code (1 = on, 0 = off)
#ifndef ENABLE_TESTS
#define ENABLE_TESTS 1
#endif

// Check every input byte in cf_enc and enforce max length / null termination (1 = on, 0 = off)
#ifndef BASE_TRUNCATE_ON_NULL
#define BASE_TRUNCATE_ON_NULL 0
#endif

#endif // CRYPTO_CONFIG_H