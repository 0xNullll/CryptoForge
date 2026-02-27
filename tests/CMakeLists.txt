cmake_minimum_required(VERSION 3.24)

# -------------------------------
# Collect all test sources
# -------------------------------
file(GLOB_RECURSE TEST_SRC
    "run_all_tests.c"       # include the main runner
    "smoke/*.c"             # all smoke tests
    "thirdparty/*.c"        # all thirdparty tests
)

# -------------------------------
# Create test executable
# -------------------------------
add_executable(cf_tests ${TEST_SRC})

# Always enable test logic
target_compile_definitions(cf_tests PRIVATE ENABLE_TESTS=1)

# Conditionally enable verbose mode
target_compile_definitions(cf_tests PRIVATE
    ENABLE_TESTS_VERBOSE=$<BOOL:${ENABLE_CF_TESTS_VERBOSE}>
)

if(CF_LINK_SHARED)
    target_link_libraries(cf_tests PRIVATE cryptoforge_shared)

    add_custom_command(TARGET cf_tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_RUNTIME_DLLS:cf_tests>
            $<TARGET_FILE_DIR:cf_tests>
        COMMAND_EXPAND_LISTS
    )
else()
    target_link_libraries(cf_tests PRIVATE cryptoforge_static)
endif()

# Include directories for headers and vectors
target_include_directories(cf_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/vectors
)

# Register with CTest
add_test(NAME CryptoForgeTests COMMAND cf_tests)