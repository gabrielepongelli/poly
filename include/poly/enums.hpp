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

        // The length of the data is not a multyple of size
        kNotAligned,

        // The access to the file specified is not permitted
        kFileAccessDenied,

        // The path of the target specified is malformed
        kMalformedPath,

        // An error occurred wile trying to write into a specific file
        kFileWritingFailed,

        // An error occurred wile trying to copy a file
        kFileCopyFailed,

        // This binary doesn't have an attached target binary to run
        kNoTargetAttached,

        // The target was not previously executed
        kTargetNotExecuted,

        // The target is already in execution
        kTargetAlreadyInExecution
    };

    enum class EncryptionAlgorithmType {
        // No encryption is performed
        kNone,

        // A xor will be used
        kXor
    };

    enum class CipherMode {
        // CBC mode will be used
        kCBC
    };

    namespace impl {

        enum class Arch { kNotSupported = 0, kSupported = 1 };

    } // namespace impl

    enum class MutationType {
        kNotSimple,
        kAndSimple,
        kOrSimple,
        kXorSimple,
        kSumSimple,
        kSubtractSimple,
        kMultiplySimple,

        // a | b = (a ^ b) + (a & b)
        kOrRecursive,

        // a ^ b = (a + b) - 2*(a & b)
        kXorRecursive,

        // a + b = (a ^ b) + 2*(a & b)
        kSumRecursive,

        // a - b = (a ^ b) - 2 * (!a & b)
        kSubtractRecursive
    };

} // namespace poly