include(Catch)

add_executable(tests 
    main.cpp
)

target_link_libraries(tests
    PRIVATE
    engine
    ${LIB_CATCH2}
)

# Automatically discover tests
catch_discover_tests(tests)