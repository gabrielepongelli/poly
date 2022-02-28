cmake_minimum_required(VERSION 3.14)
project(Poly
        VERSION 1.0.0
        LANGUAGES CXX ASM ASM_MASM)


option(BUILD_TESTING "Build test cases" ON)


# Only do these if this is the main project, and not if it is included through add_subdirectory
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)

    set(CMAKE_CXX_STANDARD 14)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_EXTENSIONS OFF)
    
    # In order not to make the linker complain about lower visibility settings 
    # in the external libraries
    set(CMAKE_CXX_VISIBILITY_PRESET hidden)

    # Support folders in IDEs
    set_property(GLOBAL PROPERTY USE_FOLDERS ON)

    # Testing only available if this is the main app
    include(CTest)

endif()


# Fetch the external libraries
include("cmake/ExternalLibs.cmake")

# Static library that contains common classes
add_subdirectory(src)


if((CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME OR MODERN_CMAKE_BUILD_TESTING) AND BUILD_TESTING)
    add_subdirectory(tests)
endif()
