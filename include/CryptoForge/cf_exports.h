/*
 * CryptoForge - cf_exports.h / High-level CryptoForge API macro
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

#ifndef CF_EXPORT_H
#define CF_EXPORT_H

/* =======================================
   Windows
   ======================================= */
#if defined(_WIN32) || defined(_WIN64)

    #if defined(CF_STATIC)
        #define CF_API

    #elif defined(CF_BUILD_SHARED)
        #define CF_API __declspec(dllexport)

    #else
        #define CF_API __declspec(dllimport)
    #endif

/* =======================================
   GCC / Clang (Linux, macOS, etc.)
   ======================================= */
#elif defined(__GNUC__) || defined(__clang__)

    #if defined(CF_BUILD_SHARED)
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