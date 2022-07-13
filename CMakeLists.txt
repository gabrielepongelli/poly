cmake_minimum_required(VERSION 3.14)
project(Poly
        VERSION 1.0.0
        LANGUAGES CXX ASM ASM_MASM)


option(POLY_BUILD_TESTING "Build test cases"    OFF)
option(POLY_BUILD_EXAMPLE "Build example"       OFF)
option(POLY_BUILD_DOC     "Build documentation" OFF)


# Only do these if this is the main project, and not if it is included through add_subdirectory
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)

    set(CMAKE_CXX_STANDARD 14)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_EXTENSIONS OFF)

    # Testing only available if this is the main app
    include(CTest)

endif()


# Fetch the external libraries
include("cmake/ExternalLibs.cmake")

set(SOURCE_DIR "${Poly_SOURCE_DIR}/src/")
set(INCLUDE_DIR "${Poly_SOURCE_DIR}/include/poly/")

# Static library that contains common classes
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/src")

if((CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME OR MODERN_CMAKE_BUILD_TESTING) AND POLY_BUILD_TESTING)
    add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/tests")
endif()

if(POLY_BUILD_EXAMPLE)
    add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/example")
endif()

if(POLY_DOC)
    add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/docs")
endif()