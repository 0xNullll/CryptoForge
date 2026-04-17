cmake_minimum_required(VERSION 3.24)

# =========================================================
# Project
# =========================================================
project(CryptoForge
    VERSION 0.1.2
    LANGUAGES C
)

# =========================================================
# Language standard
# =========================================================
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# =========================================================
# Build options
# =========================================================
option(CF_LINK_SHARED "Build library as shared (DLL/.so)" OFF)
option(CF_BUILD_TESTS "Build tests" ON)

# =========================================================
# CryptoForge configurable flags
# =========================================================
option(ENABLE_CF_BARRIER        "Enable compiler barriers" OFF)
option(ENABLE_CF_TESTS_VERBOSE  "Enable verbose demo/test output" OFF)
option(ENABLE_CF_BASE_TRUNC     "Enforce truncation on null" OFF)
option(ENABLE_CF_DEBUG          "Enable debug features" OFF)

# # =========================================================
# # Optional user-specified compiler
# # =========================================================
# set(CF_FORCE_C_COMPILER "" CACHE STRING "Optional: specify full path to C compiler")

# if(NOT CF_FORCE_C_COMPILER STREQUAL "")
#     set(CMAKE_C_COMPILER "${CF_FORCE_C_COMPILER}" CACHE STRING "C compiler" FORCE)
#     message(STATUS "Forcing C compiler to: ${CMAKE_C_COMPILER}")
# endif()

# =========================================================
# Compiler detection
# =========================================================
message(STATUS "Using ${CMAKE_C_COMPILER_ID} as native compiler")

# =========================================================
# Build types
# =========================================================
set(CMAKE_CONFIGURATION_TYPES "Debug;RelWithDebInfo;Release;MaxOptRelease" CACHE STRING "" FORCE)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the build type." FORCE)
endif()

# =========================================================
# Compiler-specific flags
# =========================================================
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_C_FLAGS_DEBUG          "-g -O0 -Wall -Wextra")
    set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g -Wall -Wextra")
    set(CMAKE_C_FLAGS_RELEASE        "-O2 -Wall -Wextra -s")
    set(CMAKE_C_FLAGS_MAXOPTRELEASE  "-O3 -march=native -flto -Wall -Wextra -s")

elseif(CMAKE_C_COMPILER_ID STREQUAL "MSVC")
    set(CMAKE_C_FLAGS_DEBUG          "/Zi /Od /W4")
    set(CMAKE_C_FLAGS_RELWITHDEBINFO "/Zi /O2 /W4")
    set(CMAKE_C_FLAGS_RELEASE        "/O2 /W4 /DNDEBUG")
    set(CMAKE_C_FLAGS_MAXOPTRELEASE  "/Ox /Oi /Ot /GL /DNDEBUG")
endif()

# =========================================================
# Subdirectories
# =========================================================
add_subdirectory(src)

# =========================================================
# Tests
# =========================================================
if(CF_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()