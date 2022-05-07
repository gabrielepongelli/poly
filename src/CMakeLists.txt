set(HEADER_LIST
    engine.hpp
    enums.hpp
    host_properties.hpp
    utils.hpp
    binary_editor.hpp
    encryption.hpp
)

set(SOURCE_LIST
    engine.tpp
    binary_editor.tpp
    utils.cpp
    utils.tpp
    encryption.tpp
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
list(TRANSFORM HEADER_LIST PREPEND "${Poly_SOURCE_DIR}/include/engine/")

add_library(engine STATIC ${HEADER_LIST} ${SOURCE_LIST})

# Required by AsmJIT to link itself statically in the correct way
target_compile_definitions(engine PUBLIC ASMJIT_STATIC)

if(MSVC)
    # Needed by LIEF for the 'and', 'or' ... keywords
    target_compile_options(engine PUBLIC /FIiso646.h)

    # Needed by LIEF to use his version of msvcrt.lib
    target_link_options(engine PUBLIC /NODEFAULTLIB:MSVCRT)
endif()

target_include_directories(engine
    PUBLIC
    "${CMAKE_SOURCE_DIR}/include"
    "${CMAKE_SOURCE_DIR}/src"
)

target_link_libraries(engine
    PUBLIC
    ${LIB_ASMJIT}
    ${LIB_LIEF}
)
