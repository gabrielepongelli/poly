include(Catch)

add_executable(tests 
    main.cpp
    unit_tests/binary_editor.cpp
    unit_tests/encryption.cpp
    integration_tests/engine.cpp
)

# Required by Boost Filesystem in order to use only not-deprecated functions
target_compile_definitions(tests PUBLIC BOOST_FILESYSTEM_NO_DEPRECATED)
# Required by AsmJIT to link itself statically in the correct way
target_compile_definitions(tests PUBLIC ASMJIT_STATIC)

target_link_libraries(tests
    PRIVATE
    poly
    ${LIB_CATCH2}
    ${LIB_LIEF}
    ${LIB_BOOST_FS}
    ${LIB_ASMJIT}
)

add_executable(hello_world
    test_binaries/hello_world.cpp
)

add_executable(engine_test
    test_binaries/engine_test.cpp
)

target_link_libraries(engine_test
    PRIVATE
    poly
    ${LIB_CATCH2}
)

set(TEST_DIR "${CMAKE_CURRENT_BINARY_DIR}")

if (MSVC)
    set(TEST_DIR "${TEST_DIR}/$<CONFIG>")
endif()

# Automatically discover tests
catch_discover_tests(tests
    WORKING_DIRECTORY "${TEST_DIR}"
)