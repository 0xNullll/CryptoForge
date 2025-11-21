#ifndef UTILS_H
#define UTILS_H

#include "../config/crypto_config.h"

// ======================
// 1. Platform / DLL / Compiler Macros
// ======================
#ifdef _WIN32
  #ifdef BUILDING_TC_DLL
    #define TC_API __declspec(dllexport)
  #else
    #define TC_API __declspec(dllimport)
  #endif
#else
  #define TC_API
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

#endif // UTILS_H
