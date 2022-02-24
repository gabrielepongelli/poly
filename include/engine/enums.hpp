#pragma once

namespace poly {

    /**
     * Enumerate the supported operating systems.
     */
    enum class HostOS { kLinux, kMacOS, kWindows, kNotSupported };

    /**
     * Enumerate the supported word sizes.
     */
    enum class WordSize { k32Bit = 4, k64Bit = 8, kNotSupported = 0 };

    namespace impl {

        enum class Arch { kNotSupported = 0, kSupported = 1 };

    } // namespace impl

} // namespace poly