cmake_minimum_required(VERSION 3.24)
project(CryptoForge LANGUAGES C)

# =========================================================
# Source directories
# =========================================================
set(SRC_DIRS
    crypto/Cipher/aes
    crypto/Cipher/chacha
    crypto/aead/aes
    crypto/aead/chacha
    crypto/hash/sha
    crypto/hash/sha/keccak
    crypto/hash/md
    crypto/mac
    crypto/kdf
    crypto/enc
    crypto/cf_api
    utils
)

# =========================================================
# Collect sources
# =========================================================
set(CF_SRC "")
foreach(dir IN LISTS SRC_DIRS)
    file(GLOB tmp "${CMAKE_CURRENT_SOURCE_DIR}/${dir}/*.c")
    list(APPEND CF_SRC ${tmp})
endforeach()

# =========================================================
# Version info
# =========================================================
if(WIN32 AND CF_LINK_SHARED)
    set(CF_RC_FILE "${CMAKE_SOURCE_DIR}/resources/CryptoForge.rc")
else()
    set(CF_RC_FILE "")
endif()

# =========================================================
# Create library
# =========================================================
if(CF_LINK_SHARED)
    add_library(cryptoforge SHARED ${CF_SRC} ${CF_RC_FILE})
else()
    add_library(cryptoforge STATIC ${CF_SRC} ${CF_RC_FILE})
endif()

# if(CF_LINK_SHARED)
#     add_library(cryptoforge SHARED ${CF_SRC})
# else()
#     add_library(cryptoforge STATIC ${CF_SRC})
# endif()

set_target_properties(cryptoforge PROPERTIES OUTPUT_NAME "cryptoforge")

# =========================================================
# Include directories
# =========================================================
target_include_directories(cryptoforge
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>  # <CryptoForge/...>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}                     # internal headers
)

# =========================================================
# Compile definitions (THIS BELONGS HERE, not tests)
# =========================================================
target_compile_definitions(cryptoforge
    PUBLIC
        ENABLE_BARRIER=$<BOOL:${ENABLE_CF_BARRIER}>
        BASE_TRUNCATE_ON_NULL=$<BOOL:${ENABLE_CF_BASE_TRUNC}>
        CF_DEBUG=$<BOOL:${ENABLE_CF_DEBUG}>
)

# DLL / Shared flags
if(CF_LINK_SHARED)
    if(WIN32)
        target_compile_definitions(cryptoforge PRIVATE BUILDING_CF_DLL=1)
    else()
        target_compile_definitions(cryptoforge PRIVATE BUILDING_CF_SHARED=1)
    endif()
else()
    target_compile_definitions(cryptoforge PRIVATE
        BUILDING_CF_DLL=0
        BUILDING_CF_SHARED=0
    )
endif()

# =========================================================
# Compiler warnings
# =========================================================
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(cryptoforge PRIVATE -Wall -Wextra -Wshadow -Wconversion)
elseif(MSVC)
    target_compile_options(cryptoforge PRIVATE /W4 /WX)
endif()

# =========================================================
# Windows shared export
# =========================================================
if(WIN32 AND CF_LINK_SHARED)
    set_target_properties(cryptoforge PROPERTIES
        WINDOWS_EXPORT_ALL_SYMBOLS ON
    )
endif()

# =========================================================
# Output directories
# =========================================================
if(OUTPUT_DIR)
    foreach(cfg IN ITEMS Debug RelWithDebInfo Release MaxOptRelease)
        string(TOUPPER "${cfg}" CFG_UPPER)

        set_target_properties(cryptoforge PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY_${CFG_UPPER} "${OUTPUT_DIR}"
            LIBRARY_OUTPUT_DIRECTORY_${CFG_UPPER} "${OUTPUT_DIR}"
            ARCHIVE_OUTPUT_DIRECTORY_${CFG_UPPER} "${OUTPUT_DIR}"
        )
    endforeach()
endif()

# =========================================================
# Windows linking
# =========================================================
if(MSVC)
    target_link_libraries(cryptoforge PRIVATE bcrypt)
endif()