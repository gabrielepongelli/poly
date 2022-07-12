cmake_minimum_required(VERSION 3.14)
project(Poly_Sample LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

########################################
############ Poly Inclusion ############
########################################

include(FetchContent)

# Url of this repo
set(POLY_URL "https://github.com/gabrielepongelli/poly.git")
set(POLY_TAG "main")

FetchContent_Declare(POLY
    GIT_REPOSITORY "${POLY_URL}"
    GIT_TAG "${POLY_TAG}"
)

set(POLY_BUILD_TESTS OFF CACHE INTERNAL "")
set(POLY_BUILD_EXAMPLE OFF CACHE INTERNAL "")

FetchContent_MakeAvailable(POLY)



########################################
########## Project Executables #########
########################################
add_executable(hello_world1 hello_world.cpp)
add_executable(hello_world2 hello_world.cpp)
add_executable(hello_world3 hello_world.cpp)
add_executable(hello_world4 hello_world.cpp)

add_executable(virus_sample virus_sample.cpp)
target_link_libraries(virus_sample PRIVATE poly)
target_include_directories(virus_sample
    PUBLIC 
    "${poly_SOURCE_DIR}/include"
)
add_dependencies(virus_sample poly)

add_custom_command(
    TARGET virus_sample
    POST_BUILD
    COMMAND "$<$<CONFIG:Release>:${CMAKE_STRIP}>"
    ARGS "$<TARGET_FILE:virus_sample>"
)