cmake_minimum_required(VERSION 3.24)

project(CryptoForge
    VERSION 0.1.3
    LANGUAGES C
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(CF_LINK_SHARED "Build library as shared (DLL/.so)" OFF)
option(CF_BUILD_TESTS "Build tests" ON)

option(ENABLE_CF_BARRIER        "Enable compiler barriers" OFF)
option(ENABLE_CF_TESTS_VERBOSE  "Enable verbose demo/test output" OFF)
option(ENABLE_CF_BASE_TRUNC     "Enforce truncation on null" OFF)
option(ENABLE_CF_DEBUG          "Enable debug features" OFF)

message(STATUS "Using ${CMAKE_C_COMPILER_ID} as native compiler")

set(CMAKE_CONFIGURATION_TYPES "Debug;RelWithDebInfo;Release;MaxOptRelease" CACHE STRING "" FORCE)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the build type." FORCE)
endif()

add_subdirectory(src)

if(CF_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()