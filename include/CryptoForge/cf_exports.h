#ifndef CF_EXPORT_H
#define CF_EXPORT_H

/*
 * CryptoForge - cf_export.h
 *
 * Defines symbol visibility macros for shared/static builds.
 *
 * Usage:
 *   - When building the library:
 *       define CF_BUILD_SHARED
 *
 *   - When using the shared library:
 *       define CF_USE_SHARED
 *
 *   - When building/using static library:
 *       define CF_STATIC
 */

/* =======================================
   Windows
   ======================================= */
#if defined(_WIN32) || defined(_WIN64)

    #if defined(CF_STATIC)
        #define CF_API

    #elif defined(CF_BUILD_SHARED)
        #define CF_API __declspec(dllexport)

    #elif defined(CF_USE_SHARED)
        #define CF_API __declspec(dllimport)

    #else
        #define CF_API
    #endif

/* =======================================
   GCC / Clang (Linux, macOS, etc.)
   ======================================= */
#elif defined(__GNUC__) || defined(__clang__)

    #if defined(CF_STATIC)
        #define CF_API

    #elif defined(CF_BUILD_SHARED)
        #define CF_API __attribute__((visibility("default")))

    #else
        #define CF_API
    #endif

/* =======================================
   Fallback
   ======================================= */
#else
    #define CF_API
#endif

#endif // CF_EXPORT_H