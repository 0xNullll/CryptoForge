/*
 * CryptoForge - misc_utils.h / Miscellaneous Utilities
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

#ifndef MISC_UTILS_H
#define MISC_UTILS_H

#include "../config/crypto_config.h"
#include "../config/libs.h"

#ifdef _WIN32
  #ifdef BUILDING_CF_DLL
    #define CF_API __declspec(dllexport)
  #else
    #define CF_API __declspec(dllimport)
  #endif
#else
  #define CF_API
#endif

#ifdef CF_DEBUG
    #define CF_ASSERT(expr) assert(expr)
#else
    #define CF_ASSERT(expr) ((void)0)
#endif

#ifdef _MSC_VER
  #define FORCE_INLINE __forceinline
#else
  #define FORCE_INLINE inline __attribute__((always_inline))
#endif

#if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
  #define U64(C) C##UI64
#elif defined(__arch64__)
  #define U64(C) C##UL
#else
  #define U64(C) C##ULL
#endif

#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define CPU_BIG_ENDIAN 1
#elif defined(_BIG_ENDIAN) || defined(__BIG_ENDIAN__) || defined(__ARMEB__) || defined(__MIPSEB__)
#define CPU_BIG_ENDIAN 1
#else
#define CPU_BIG_ENDIAN 0
#endif

#ifndef UNUSED
#define UNUSED(x) ((void)(x))  /* silence unused variable warnings */
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#endif // MISC_UTILSH