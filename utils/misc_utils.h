/*
 * CryptoForge - misc_utils.h / Miscellaneous Utilities
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

#ifndef MISC_UTILS_H
#define MISC_UTILS_H

#include "../config/crypto_config.h"
#include "../config/libs.h"

// ======================
// 1. Platform / DLL / Compiler Macros
// ======================
#ifdef _WIN32
  #ifdef BUILDING_CF_DLL
    #define CF_API __declspec(dllexport)
  #else
    #define CF_API __declspec(dllimport)
  #endif
#else
  #define CF_API
#endif

#ifdef _MSC_VER
  #define FORCE_INLINE __forceinline
#else
  #define FORCE_INLINE inline __attribute__((always_inline))
#endif

// ======================
// 2. Integer Literal Macros
// ======================
#if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
  #define U64(C) C##UI64
#elif defined(__arch64__)
  #define U64(C) C##UL
#else
  #define U64(C) C##ULL
#endif

// ======================
// 3. Parameter Annotations
// ======================
#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef INOUT
#define INOUT
#endif

#endif // MISC_UTILSH
