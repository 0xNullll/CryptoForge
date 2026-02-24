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

# Link against the CryptoForge library
if(CF_LINK_SHARED)
    target_link_libraries(cf_tests PRIVATE cryptoforge_shared)
    
    # Copy DLL next to the test EXE after build
    add_custom_command(TARGET cf_tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:cryptoforge_shared>
        $<TARGET_FILE_DIR:cf_tests>
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