/*
 * CryptoForge - misc_utils.h / Miscellaneous Utilities
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 *
 * Note: This library is educational, software-only, and verified only
 * against WyChaProof test vectors. No hardware optimizations. Use with caution.
 *
 * Project repository: https://github.com/0xNullll/CryptoForge
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

#endif // MISC_UTILSH