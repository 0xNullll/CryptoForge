cmake_minimum_required(VERSION 3.24)
project(CryptoForge LANGUAGES C)

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

set(CF_SRC "")
foreach(dir IN LISTS SRC_DIRS)
    file(GLOB tmp "${CMAKE_CURRENT_SOURCE_DIR}/${dir}/*.c")
    list(APPEND CF_SRC ${tmp})
endforeach()

if(WIN32 AND CF_LINK_SHARED)
    set(CF_RC_FILE "${CMAKE_SOURCE_DIR}/resources/CryptoForge.rc")
else()
    set(CF_RC_FILE "")
endif()

if(CF_LINK_SHARED)
    add_library(cryptoforge SHARED ${CF_SRC} ${CF_RC_FILE})
else()
    add_library(cryptoforge STATIC ${CF_SRC} ${CF_RC_FILE})
endif()


set_target_properties(cryptoforge PROPERTIES OUTPUT_NAME "cryptoforge")

target_include_directories(cryptoforge
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>  # <CryptoForge/...>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}                     # internal headers
)

target_compile_definitions(cryptoforge
    PUBLIC
        ENABLE_BARRIER=$<BOOL:${ENABLE_CF_BARRIER}>
        ENABLE_TESTS=$<BOOL:${CF_BUILD_TESTS}>
        ENABLE_TESTS_VERBOSE=$<BOOL:${ENABLE_CF_TESTS_VERBOSE}>
        BASE_TRUNCATE_ON_NULL=$<BOOL:${ENABLE_CF_BASE_TRUNC}>
        CF_DEBUG=$<BOOL:${ENABLE_CF_DEBUG}>
)

if(CF_LINK_SHARED)
    target_compile_definitions(cryptoforge
        PRIVATE CF_BUILD_SHARED=1
    )
else()
    target_compile_definitions(cryptoforge
        PUBLIC CF_STATIC=1
    )
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")

    target_compile_options(cryptoforge PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Werror
        -Wshadow
        -Wconversion
        -Wsign-conversion
        -Wformat=2
        -Wundef
        -Wcast-align
        -Wcast-qual
        -Wstrict-prototypes
        -Wmissing-prototypes
        -Wwrite-strings
        -Wredundant-decls
        -Wswitch-enum
        -Wuninitialized
        -Wvla

        -D_FORTIFY_SOURCE=3
        -fstack-protector-strong
        -fno-omit-frame-pointer
        -fno-strict-aliasing
        -fwrapv
    )

    # Debug-only (safe for MinGW)
    target_compile_options(cryptoforge PRIVATE
        $<$<CONFIG:Debug>:-g>
        $<$<CONFIG:Debug>:-O1>
    )

    # Release tuning
    target_compile_options(cryptoforge PRIVATE
        $<$<CONFIG:Release>:-O2>
        $<$<CONFIG:RelWithDebInfo>:-O2 -g>
    )

    # Optional constant-time safety
    target_compile_options(cryptoforge PRIVATE
        -fno-tree-vectorize
    )

elseif(MSVC)

    target_compile_options(cryptoforge PRIVATE
        /W4
        /WX
        $<$<CONFIG:Debug>:/Zi /Od>
        $<$<CONFIG:Release>:/O2 /DNDEBUG>
    )

endif()

if(WIN32 AND CF_LINK_SHARED)
    set_target_properties(cryptoforge PROPERTIES
        WINDOWS_EXPORT_ALL_SYMBOLS ON
    )
endif()

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

if(MSVC)
    target_link_libraries(cryptoforge PRIVATE bcrypt)
endif()