#pragma once

#include <cstdint>

#include <bitset>
#include <type_traits>
#include <utility>

#include "code_container.hpp"
#include "enums.hpp"
#include "host_properties.hpp"
#include "utils.hpp"

namespace poly {

    /**
     * A Block of N bytes represents an interface for a block of memory which
     * can be seen and manipulated with bitwise operations as a single memory
     * unit of fixed length.
     */
    template <std::size_t bytes>
    using Block = typename std::conditional<
        bytes == 1, std::uint8_t,
        typename std::conditional<
            bytes == 2, std::uint16_t,
            typename std::conditional<
                bytes == 4, std::uint32_t,
                typename std::conditional<bytes == 8, std::uint64_t,
                                          std::bitset<bytes * 8>>::type>::
                type>::type>::type;

    namespace impl {

        /**
         * The BlockBuilder is an interface for the generations of new Block
         * object from arrays of bytes. The size of the Block to construct has
         * to be specified by the non-type template parameter bytes.
         */
        template <std::size_t bytes, std::size_t check = bytes,
                  typename = impl::range<>>
        struct BlockBuilder {

            /**
             * Build a Block from the specified pointer.
             * @param ptr pointer to the first byte. WARNING: the method assumes
             * that the pointer passed is NOT NULL.
             * @returns a Block with the first n bytes of ptr stored in little
             * endian.
             */
            static Block<bytes> build(std::uint8_t *ptr) noexcept;

            /**
             * Store the content of the specified Block in the first n bytes of
             * the specified pointer.
             * @param b block to transfer. The content will be treated as a
             * little endian value, therefore the bytes of b will be saved in
             * reverse order.
             * @param ptr pointer to the first byte that will be modified.
             * WARNING: the method assumes that the pointer passed is NOT NULL.
             */
            static void to_bytes(Block<bytes> &b, std::uint8_t *ptr) noexcept;
        };

        template <std::size_t bytes, std::size_t check>
        struct BlockBuilder<
            bytes, check,
            impl::range<(bytes == 2 || bytes == 4 || bytes == 8)>> {
            static Block<bytes> build(std::uint8_t *ptr) noexcept;

            static void to_bytes(Block<bytes> &b, std::uint8_t *ptr) noexcept;
        };

        template <std::size_t check>
        struct BlockBuilder<1, check, impl::range<>> {
            static Block<1> build(std::uint8_t *ptr) noexcept;

            static void to_bytes(Block<1> &b, std::uint8_t *ptr) noexcept;
        };

        template <std::size_t check>
        struct BlockBuilder<0, check, impl::range<>> {
            static_assert(check > 0,
                          "The number of bytes must be greater than 0.");
        };

    } // namespace impl

    template <std::size_t bytes>
    using BlockBuilder = impl::BlockBuilder<bytes>;

    /**
     * An EncryptionSecret is a structure created to hold an initialization
     * vector and a key to use, which size in bytes is specified by the non-type
     * template parameter size. If that parameter is 0 a compile-time error will
     * be raised.
     * This type does not provide any methods useful to handle the data, it's
     * only a structure created to wrap them.
     */
    template <std::uint8_t size>
    struct EncryptionSecret {

        static_assert(size > 0, "The size (in bytes) must be greater than 0.");

        Block<size> iv;
        Block<size> key;

        EncryptionSecret(Block<size> iv, Block<size> key);
    };

    /**
     * An EncryptionAlgorithm implement the algorithm to use for the encryption
     * and the decryption. The right algorithm to use must be specified through
     * the non-type template parameter E, which defaults to kNone.
     */
    template <EncryptionAlgorithmType E = EncryptionAlgorithmType::kNone>
    struct EncryptionAlgorithm {

        /**
         * Encrypt the specified block of data with the specified encryption
         * secret.
         */
        template <std::uint8_t size = kByteWordSize>
        static void encrypt(const EncryptionSecret<size> &secret,
                            Block<size> &data);

        /**
         * Generate the assembly code to decrypt the data inside the register
         * specified with the key specified. The result will be saved in the
         * data register.
         * @param key register that contains the key to use in the decryption.
         * Its content will not be modified.
         * @param data register that contains the data to decrypt. Its content
         * will be overwritten with the result.
         * @param c compiler to use for the generation of the assembly code.
         */
        template <std::uint8_t size = kByteWordSize>
        static void assemble_decryption(Register &key, Register &data,
                                        Compiler &c);
    };

    template <>
    struct EncryptionAlgorithm<EncryptionAlgorithmType::kXor> {
        template <std::uint8_t size = kByteWordSize>
        static void encrypt(const EncryptionSecret<size> &secret,
                            Block<size> &data);

        template <std::uint8_t size = kByteWordSize>
        static void assemble_decryption(Register &key, Register &data,
                                        Compiler &c);
    };

    namespace impl {

        template <CipherMode M, class Enc>
        struct CipherImpl;

        template <class Enc>
        struct CipherImpl<CipherMode::kCBC, Enc> {
            template <std::uint8_t size>
            static Error encrypt(std::uint8_t *data, std::size_t len,
                                 const EncryptionSecret<size> &secret);

            template <std::uint8_t size = 8>
            static Error
            assemble_decryption(const EncryptionSecret<size> &secret,
                                Compiler &c, const Register &data_ptr,
                                std::size_t data_len,
                                const asmjit::Label &exit_label);
        };

        template <class T, typename... Args>
        using encrypt_t = decltype(std::declval<T>().template encrypt(
            std::declval<Args>()...));

        template <class T, typename... Args>
        using supports_encrypt = is_detected<encrypt_t, T, Args...>;

        template <class T, typename... Args>
        using assemble_decryption_t =
            decltype(std::declval<T>().template assemble_decryption(
                std::declval<Args>()...));

        template <class T, typename... Args>
        using supports_assemble_decryption =
            is_detected<assemble_decryption_t, T, Args...>;

    } // namespace impl

    /**
     * A Cipher implement a use mode for the specified encryption algorithm. The
     * mode to use has to be specified with the non-type template parameter M,
     * whereas the encryption algorithm to use has to be specified with the
     * template parameter Enc. Enc must adhere to this constraints:
     * - must implement a static template method with this signature:
     *      template <std::uint8_t size>
     *      void encrypt(const EncryptionSecret<size> &, Block<size> &);
     * - must implement a static template method with this signature:
     *      template <std::uint8_t size>
     *      void assemble_decryption(Register &, Register &, Compiler &);
     * If any of this constraints isn't respected a compile-time error will be
     * raised.
     */
    template <CipherMode M, class Enc>
    struct Cipher {

        /**
         * Encrypt the specified data with the specified encryption secret. The
         * procedure will overwrite the plain data with the encrypted ones.
         * @param data pointer to the first byte to encrypt. WARNING: the method
         * assumes that the pointer passed is NOT NULL.
         * @param len number of bytes of the data to encrypt. If is 0 this
         * procedure does nothing. If its value is not a multiple of the
         * non-type template parameter size, nothing will be modified and an
         * error will be returned.
         * @param secret encryption secret to use.
         * @returns kNone if no error has occurred.
         */
        template <std::uint8_t size = kByteWordSize>
        static Error encrypt(std::uint8_t *data, std::size_t len,
                             const EncryptionSecret<size> &secret);

        /**
         * Generate the assembly code to decrypt the data specified with the
         * encryption secret specified.
         * @param secret encryption secret to use.
         * @param c compiler to use for the generation of the assembly code.
         * @param data_ptr register which contain the address to the first byte
         * to encrypt. WARNING: the method assumes that the address passed is a
         * valid one. When the procedure terminate (without errors) this
         * register will contain the memory address of the first byte after the
         * encrypted data.
         * @param data_len number of bytes of the data to encrypt. If its value
         * is not a multiple of the non-type template parameter size, nothing
         * will be modified and an error will be returned.
         * @param exit_label label that indicates the exit of the assembled
         * procedure. When the assembled assembly code will be executed, it will
         * jump to this label at the end of the decryption.
         * @returns kNone if no error has occurred.
         */
        template <std::uint8_t size = kByteWordSize>
        static Error assemble_decryption(const EncryptionSecret<size> &secret,
                                         Compiler &c, const Register &data_ptr,
                                         std::size_t data_len,
                                         const asmjit::Label &exit_label);
    };

} // namespace poly

#include "encryption.tpp"