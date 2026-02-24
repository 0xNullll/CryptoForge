cmake_minimum_required(VERSION 3.24)

project(CryptoForge
    VERSION 1.0
    LANGUAGES C
)

# -------------------------------
# Force C11 standard
# -------------------------------
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# -------------------------------
# Build options
# -------------------------------
option(CF_LINK_SHARED "Build and link tests against shared library" OFF)
option(CF_BUILD_TESTS "Build tests" ON)

# -------------------------------
# CryptoForge configurable flags
# -------------------------------
option(ENABLE_CF_BARRIER "Enable compiler barriers" OFF)
option(ENABLE_CF_DEBUG   "Enable debug mode" ON)
option(ENABLE_CF_TESTS   "Enable demo/test code" OFF)
option(ENABLE_BASE_TRUNC "Enforce truncation on null" OFF)

add_compile_definitions(
    CF_ENABLE_BARRIER=$<BOOL:${ENABLE_CF_BARRIER}>
    CF_DEBUG=$<BOOL:${ENABLE_CF_DEBUG}>
    ENABLE_TESTS=$<BOOL:${ENABLE_CF_TESTS}>
    BASE_TRUNCATE_ON_NULL=$<BOOL:${ENABLE_BASE_TRUNC}>
)

# -------------------------------
# Detect compiler
# -------------------------------
if(CMAKE_C_COMPILER_ID STREQUAL "MSVC")
    message(STATUS "Using MSVC as native compiler")
elseif(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    message(STATUS "Using GCC as native compiler")
elseif(CMAKE_C_COMPILER_ID STREQUAL "Clang")
    message(STATUS "Using Clang as native compiler")
else()
    message(WARNING "Unknown compiler, cross-compiler? Check build environment")
endif()

# -------------------------------
# Define build types
# -------------------------------
set(CMAKE_CONFIGURATION_TYPES "Debug;RelWithDebInfo;Release;MaxOptRelease" CACHE STRING "" FORCE)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the build type." FORCE)
endif()

# -------------------------------
# Compiler-specific flags
# -------------------------------
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_C_FLAGS_DEBUG        "-g -O0 -Wall -Wextra")
    set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g -Wall -Wextra")
    set(CMAKE_C_FLAGS_RELEASE      "-O2 -Wall -Wextra -s")
    set(CMAKE_C_FLAGS_MAXOPTRELEASE "-O3 -march=native -flto -Wall -Wextra -s")
elseif(CMAKE_C_COMPILER_ID STREQUAL "MSVC")
    set(CMAKE_C_FLAGS_DEBUG        "/Zi /Od /W4")
    set(CMAKE_C_FLAGS_RELWITHDEBINFO "/Zi /O2 /W4")
    set(CMAKE_C_FLAGS_RELEASE      "/O2 /W4 /DNDEBUG")
    set(CMAKE_C_FLAGS_MAXOPTRELEASE "/Ox /Oi /Ot /GL /DNDEBUG")
endif()

# -------------------------------
# Add library subdirectory
# -------------------------------
add_subdirectory(src/CryptoForge)

# -------------------------------
# Add tests
# -------------------------------
if(CF_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()