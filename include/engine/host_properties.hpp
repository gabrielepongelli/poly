#pragma once

#include <type_traits>

#include "enums.hpp"

namespace poly {

#if defined(__linux__)
#define HOST_OS kLinux
#define POLY_LINUX
#elif defined(_WIN32) || defined(_WIN64)
#define HOST_OS kWindows
#define POLY_WINDOWS
#elif defined(__APPLE__)
#define HOST_OS kMacOS
#define POLY_MACOS
#else
#define HOST_OS kNotSupported
#endif

    // Define the OS to use in the project's configurations.
    constexpr HostOS kOS = HostOS::HOST_OS;

    namespace impl {
        template <class T, T _Val>
        struct is_supported : std::false_type {};

        template <HostOS _Val>
        struct is_supported<HostOS, _Val>
            : std::conditional<_Val != HostOS::kNotSupported, std::true_type,
                               std::false_type> {};

        template <HostOS O>
        struct is_os_supported : is_supported<HostOS, O> {
            static constexpr bool value = is_supported<HostOS, O>::type::value;
        };

        static_assert(is_os_supported<kOS>::value,
                      "This project does not support your operating system.");
    } // namespace impl

#undef HOST_OS

#if (defined(__clang__) || defined(__llvm__)) &&                               \
    (defined(__i386__) || defined(__x86_64__))
#define HOST_ARCH kSupported
#elif defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))
#define HOST_ARCH kSupported
#elif defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64))
#define HOST_ARCH kSupported
#else
#define HOST_ARCH kNotSupported
#endif

    namespace impl {
        constexpr Arch kArch = Arch::HOST_ARCH;

        template <Arch _Val>
        struct is_supported<Arch, _Val>
            : std::conditional<_Val != Arch::kNotSupported, std::true_type,
                               std::false_type> {};

        template <Arch A>
        struct is_arch_supported : is_supported<Arch, A> {
            static constexpr bool value = is_supported<Arch, A>::type::value;
        };

        static_assert(is_arch_supported<kArch>::value,
                      "This project does not support your architecture.");
    } // namespace impl

#undef HOST_ARCH

    // Define the word size to use in the project's configurations.
    constexpr WordSize kWordSize = static_cast<WordSize>(sizeof(void *));

    namespace impl {
        template <WordSize _Val>
        struct is_supported<WordSize, _Val>
            : std::conditional<_Val != WordSize::kNotSupported, std::true_type,
                               std::false_type> {};

        template <WordSize WS>
        struct is_word_size_supported : is_supported<WordSize, WS> {
            static constexpr bool value =
                is_supported<WordSize, WS>::type::value;
        };

        static_assert(
            is_word_size_supported<kWordSize>::value,
            "This project supports only 32- and 64-bit architectures.");
    } // namespace impl

} // namespace poly