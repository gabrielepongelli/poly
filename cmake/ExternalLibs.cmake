include(FetchContent)

find_package(Git REQUIRED)


# -------------------------------------------
#                 AsmJIT
# -------------------------------------------
set(ASMJIT asmjit)
set(ASMJIT_URL "https://github.com/asmjit/asmjit.git")
set(ASMJIT_VERSION 9a92d2f97260749f6f29dc93e53c743448f0137a)


FetchContent_Declare(${ASMJIT}
    GIT_REPOSITORY ${ASMJIT_URL}
    GIT_TAG ${ASMJIT_VERSION}
    UPDATE_DISCONNECTED ON
)

set(ASMJIT_STATIC ON CACHE INTERNAL "Build the library statically")


# -------------------------------------------
#                 LIEF
# -------------------------------------------
set(LIEF LIEF)
set(LIEF_URL "https://github.com/lief-project/LIEF.git")
set(LIEF_VERSION c7b3ce3b2ce6917855a72709f73ef6d00b50e1f7)


FetchContent_Declare(${LIEF}
    GIT_REPOSITORY ${LIEF_URL}
    GIT_TAG ${LIEF_VERSION}
    UPDATE_DISCONNECTED ON
)


# LIEF compilation config
set(LIEF_USE_CCACHE     OFF CACHE INTERNAL "Do not use ccache")
set(LIEF_DOC            OFF CACHE INTERNAL "Do not generate lief documentation")
set(LIEF_PYTHON_API     OFF CACHE INTERNAL "Do not include python api")
set(LIEF_EXAMPLES       OFF CACHE INTERNAL "Do not build examples")
set(LIEF_TESTS          OFF CACHE INTERNAL "Do not run tests")
set(LIEF_C_API          OFF CACHE INTERNAL "Do not include C api")
set(LIEF_ENABLE_JSON    OFF CACHE INTERNAL "Do not include json api")
set(LIEF_DEX            OFF CACHE INTERNAL "Do not include support for DEX executable format")
set(LIEF_ART            OFF CACHE INTERNAL "Do not include support for ART executable format")
set(LIEF_OAT            OFF CACHE INTERNAL "Do not include support for OAT executable format")
set(LIEF_VDEX           OFF CACHE INTERNAL "Do not include support for VDEX executable format")

# Compile only platform specific module
if(NOT ${CMAKE_HOST_SYSTEM_NAME} MATCHES "Windows")
    set(LIEF_PE OFF CACHE INTERNAL "Do not include support for PE executable format")
else()
    if(MSVC)
        set(LIEF_USE_CRT_DEBUG MDd CACHE INTERNAL "Set the correct build configuration")
        set(LIEF_USE_CRT_RELEASE MT CACHE INTERNAL "Set the correct build configuration")
        set(LIEF_USE_CRT_MINSIZEREL MT CACHE INTERNAL "Set the correct build configuration")
        set(LIEF_USE_CRT_RELWITHDEBINFO MTd CACHE INTERNAL "Set the correct build configuration")
    endif()
endif()

if(NOT ${CMAKE_HOST_SYSTEM_NAME} MATCHES "Darwin")
    set(LIEF_MACHO OFF CACHE INTERNAL "Do not include support for MACHO executable format")
endif()

if(NOT ${CMAKE_HOST_SYSTEM_NAME} MATCHES "Linux")
    set(LIEF_ELF OFF CACHE INTERNAL "Do not include support for ELF executable format")
endif()

# Enable logging only during debug
if(${CMAKE_BUILD_TYPE} MATCHES ".*Deb.*")
    set(LIEF_LOGGING       ON CACHE INTERNAL "Enable logging")
    set(LIEF_LOGGING_DEBUG ON CACHE INTERNAL "Enable logging")
else()
    set(LIEF_LOGGING       OFF CACHE INTERNAL "Disable logging")
    set(LIEF_LOGGING_DEBUG OFF CACHE INTERNAL "Disable logging")
endif()


# -------------------------------------------
#                 Catch2
# -------------------------------------------
set(CATCH2 Catch2)
set(CATCH2_URL "https://github.com/catchorg/Catch2.git")
set(CATCH2_VERSION v2.13.8)


FetchContent_Declare(Catch2
    GIT_REPOSITORY ${CATCH2_URL}
    GIT_TAG        ${CATCH2_VERSION}
    UPDATE_DISCONNECTED ON
)

FetchContent_MakeAvailable(${ASMJIT} ${LIEF} ${CATCH2})

# Target libraries to link
set(LIB_LIEF    LIB_LIEF)
set(LIB_ASMJIT  asmjit)
set(LIB_CATCH2  Catch2)

# Add the catch modules' path to the global path
list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/contrib)