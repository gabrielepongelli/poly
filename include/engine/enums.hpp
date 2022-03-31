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

    enum class Error {
        // No error has occurred
        kNone,

        // The section specified was not found
        kSectionNotFound,

        // The section specified is already present in the binary
        kSectionAlreadyExists,

        // The offset specified exceed the size of the section specified
        kInvalidOffset,

        // The operand specified is not valid
        kInvalidOperand,

        // The operand specified has been marked as untouchable
        kOperandIsUntouchable,
    };

    namespace impl {

        enum class Arch { kNotSupported = 0, kSupported = 1 };

    } // namespace impl

} // namespace poly