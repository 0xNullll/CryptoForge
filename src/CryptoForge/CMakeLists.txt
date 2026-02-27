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
# Create static or shared library
# -------------------------------
if(CF_LINK_SHARED)
    add_library(cryptoforge SHARED $<TARGET_OBJECTS:cryptoforge_obj>)
else()
    add_library(cryptoforge STATIC $<TARGET_OBJECTS:cryptoforge_obj>)
endif()

set_target_properties(cryptoforge PROPERTIES OUTPUT_NAME "cryptoforge")

# -------------------------------
# Optional Windows libraries
# -------------------------------
if(MSVC)
    target_link_libraries(cryptoforge PRIVATE bcrypt)
endif()