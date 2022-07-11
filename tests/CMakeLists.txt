include(Catch)

add_executable(tests 
    main.cpp
    unit_tests/binary_editor.cpp
    unit_tests/encryption.cpp
    unit_tests/ocompiler.cpp
    integration_tests/engine.cpp
    integration_tests/virus.cpp
)

# Required by AsmJIT to link itself statically in the correct way
target_compile_definitions(tests PUBLIC ASMJIT_STATIC)

target_link_libraries(tests
    PRIVATE
    poly
    ${LIB_CATCH2}
    ${LIB_LIEF}
    ${LIB_ASMJIT}
)

add_executable(hello_world
    test_binaries/hello_world.cpp
)

add_executable(file_test
    test_binaries/file_test.cpp
)

add_executable(engine_test
    test_binaries/engine_test.cpp
)

target_link_libraries(engine_test
    PRIVATE
    poly
    ${LIB_CATCH2}
)

add_executable(virus_test
    test_binaries/virus_test.cpp
)

target_link_libraries(virus_test
    PRIVATE
    poly
)

set(TEST_DIR "${CMAKE_CURRENT_BINARY_DIR}")

if (MSVC)
    set(TEST_DIR "${TEST_DIR}/$<CONFIG>")
endif()

# Automatically discover tests
catch_discover_tests(tests
    WORKING_DIRECTORY "${TEST_DIR}"
)