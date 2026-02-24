cmake_minimum_required(VERSION 3.24)
project(CryptoForge LANGUAGES C)

# -------------------------------
# Explicit source directories
# -------------------------------
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

# -------------------------------
# Collect all .c files
# -------------------------------
set(CF_SRC "")
foreach(dir IN LISTS SRC_DIRS)
    file(GLOB tmp "${CMAKE_CURRENT_SOURCE_DIR}/${dir}/*.c")
    list(APPEND CF_SRC ${tmp})
endforeach()

# -------------------------------
# Create object library (common)
# -------------------------------
add_library(cryptoforge_obj OBJECT ${CF_SRC})

# -------------------------------
# Include directories
# -------------------------------
target_include_directories(cryptoforge_obj
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include/cf_api  # public headers
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}                 # private headers
)

# -------------------------------
# Compiler warnings
# -------------------------------
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(cryptoforge_obj PRIVATE -Wall -Wextra -Wshadow -Wconversion)
elseif(MSVC)
    target_compile_options(cryptoforge_obj PRIVATE /W4 /WX)
endif()

# -------------------------------
# Create static library
# -------------------------------
add_library(cryptoforge_static STATIC $<TARGET_OBJECTS:cryptoforge_obj>)
set_target_properties(cryptoforge_static PROPERTIES OUTPUT_NAME "cryptoforge")

# -------------------------------
# Optional shared library
# -------------------------------
if(CF_LINK_SHARED)
    add_library(cryptoforge_shared SHARED $<TARGET_OBJECTS:cryptoforge_obj>)
    set_target_properties(cryptoforge_shared PROPERTIES OUTPUT_NAME "cryptoforge")
endif()

# -------------------------------
# Optional Windows libraries
# -------------------------------
if(MSVC)
    target_link_libraries(cryptoforge_static PRIVATE bcrypt)
    if(CF_LINK_SHARED)
        target_link_libraries(cryptoforge_shared PRIVATE bcrypt)
    endif()
endif()