cmake_minimum_required(VERSION 3.24)

project(CryptoForge
    VERSION 0.1.0
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
option(CF_LINK_SHARED "Build library as shared (DLL/.so)" OFF)
option(CF_BUILD_TESTS "Build tests" ON)

# -------------------------------
# CryptoForge configurable flags
# -------------------------------
option(ENABLE_CF_BARRIER        "Enable compiler barriers" OFF)
option(ENABLE_CF_TESTS          "Enable demo/test code" OFF)
option(ENABLE_CF_TESTS_VERBOSE  "Enable verbose demo/test output" OFF)
option(ENABLE_CF_BASE_TRUNC     "Enforce truncation on null" OFF)
option(ENABLE_CF_DEBUG          "Enable debug features" OFF)

# -------------------------------
# Map flags to preprocessor macros
# -------------------------------
# BUILDING_CF_DLL / BUILDING_CF_SHARED
if(CF_LINK_SHARED)
    if(WIN32)
        set(BUILDING_CF_DLL ON)
        add_compile_definitions(BUILDING_CF_DLL=1)
    elseif(UNIX)
        set(BUILDING_CF_SHARED ON)
        add_compile_definitions(BUILDING_CF_SHARED=1)
    endif()
else()
    add_compile_definitions(
        BUILDING_CF_DLL=0
        BUILDING_CF_SHARED=0
    )
endif()

# Other configurable macros
add_compile_definitions(
    ENABLE_BARRIER=$<BOOL:${ENABLE_CF_BARRIER}>
    ENABLE_TESTS=$<BOOL:${ENABLE_CF_TESTS}>
    ENABLE_TESTS_VERBOSE=$<BOOL:${ENABLE_CF_TESTS_VERBOSE}>
    BASE_TRUNCATE_ON_NULL=$<BOOL:${ENABLE_CF_BASE_TRUNC}>
    CF_DEBUG=$<BOOL:${ENABLE_CF_DEBUG}>
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
# Optional user-specified output folder
# -------------------------------
set(OUTPUT_DIR "" CACHE PATH "Optional folder to drop build artifacts into")
if(NOT OUTPUT_DIR STREQUAL "")
    # Single-configuration generators
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${OUTPUT_DIR}")
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${OUTPUT_DIR}")
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${OUTPUT_DIR}")

    # Multi-configuration generators (Visual Studio, Xcode)
    foreach(OUTPUTCONFIG IN ITEMS Debug RelWithDebInfo Release MaxOptRelease)
        string(TOUPPER "${OUTPUTCONFIG}" OUTPUTCONFIG_UPPER)
        set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${OUTPUTCONFIG_UPPER} "${OUTPUT_DIR}")
        set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${OUTPUTCONFIG_UPPER} "${OUTPUT_DIR}")
        set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${OUTPUTCONFIG_UPPER} "${OUTPUT_DIR}")
    endforeach()
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