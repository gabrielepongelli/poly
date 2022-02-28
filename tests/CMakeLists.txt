include(Catch)

add_executable(tests 
    main.cpp
    unit_tests/binary_editor.cpp
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

# Automatically discover tests
catch_discover_tests(tests)