cmake_minimum_required(VERSION 3.24)

# =========================================================
# Collect all test sources
# =========================================================
file(GLOB_RECURSE TEST_SRC
    "cf_tests.c"
    "smoke/*.c"
    "thirdparty/*.c"
)

# =========================================================
# Version info
# =========================================================
if(WIN32)
    set(CF_RC_FILE "${CMAKE_SOURCE_DIR}/resources/cf_tests.rc")
else()
    set(CF_RC_FILE "")
endif()

# =========================================================
# Create test executable
# =========================================================
add_executable(cf_tests
    ${TEST_SRC}
    ${CF_RC_FILE}
)

# =========================================================
# Compile definitions (tests only)
# =========================================================
target_compile_definitions(cf_tests PRIVATE
    ENABLE_TESTS=1
    ENABLE_TESTS_VERBOSE=$<BOOL:${ENABLE_CF_TESTS_VERBOSE}>
)

# =========================================================
# Link with library
# =========================================================
target_link_libraries(cf_tests PRIVATE cryptoforge)

# =========================================================
# Windows DLL copy (for shared builds)
# =========================================================
if(CF_LINK_SHARED AND WIN32)
    add_custom_command(TARGET cf_tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_RUNTIME_DLLS:cf_tests>
            $<TARGET_FILE_DIR:cf_tests>
        COMMAND_EXPAND_LISTS
    )
endif()

# =========================================================
# Include directories
# =========================================================
target_include_directories(cf_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/vectors
)

# =========================================================
# Register with CTest
# =========================================================
add_test(NAME CryptoForgeTests COMMAND cf_tests)