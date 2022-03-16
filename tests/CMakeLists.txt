include(Catch)

add_executable(tests 
    main.cpp
    unit_tests/binary_editor.cpp
    unit_tests/code_container.cpp
)

target_link_libraries(tests
    PRIVATE
    engine
    ${LIB_CATCH2}
    ${LIB_LIEF}
)

add_executable(hello_world
    test_binaries/hello_world.cpp
)

set(TEST_DIR "${CMAKE_CURRENT_BINARY_DIR}")

if (MSVC)
    set(TEST_DIR "${TEST_DIR}/$<CONFIG>")
endif()

# Automatically discover tests
catch_discover_tests(tests
    WORKING_DIRECTORY "${TEST_DIR}"
)

message(STATUS "CMAKE_CURRENT_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}")