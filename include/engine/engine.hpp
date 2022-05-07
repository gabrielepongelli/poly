#pragma once

#include <cstdint>

#include <memory>
#include <type_traits>
#include <utility>

#include <asmjit/asmjit.h>

#include "binary_editor.hpp"
#include "encryption.hpp"
#include "enums.hpp"
#include "host_properties.hpp"
#include "utils.hpp"

namespace poly {

    namespace impl {

        template <class T, typename... Args>
        using complete_assemble_decryption_t = std::enable_if<
            std::is_same<assemble_decryption_t<T, Args...>, poly::Error>::value,
            assemble_decryption_t<T, Args...>>;

        template <class T, typename... Args>
        using supports_decryption =
            is_detected_t<complete_assemble_decryption_t, T, Args...>;

        template <class T, typename... Args>
        using complete_encrypt_t = std::enable_if<
            std::is_same<encrypt_t<T, Args...>, poly::Error>::value,
            encrypt_t<T, Args...>>;

        template <class T, typename... Args>
        using supports_encryption =
            is_detected_t<complete_encrypt_t, T, Args...>;

        /**
         * Abstract class that implement some methods common for all the OS.
         * It requires to the concrete class that extends it to implement the
         * following protected member methods:
         * - void generate_syscall(Address, std::size_t, asmjit::Label &);
         */
        template <class Real, class Cipher, class Compiler, class Editor>
        class PolymorphicEngineBase : public Crtp<Real> {
          public:
            PolymorphicEngineBase(BinaryEditor<Editor> &editor,
                                  std::unique_ptr<Compiler> compiler) noexcept;

            /**
             * Generate the code that will decrypt the text section with the
             * specified encryption secret.
             * @param secret secret informations to use in the decryption
             * procedure.
             */
            template <std::uint8_t word_size = kByteWordSize>
            void generate_code(const EncryptionSecret<word_size> &secret);

            /**
             * Encrypt the text section of the binary with the specified
             * encryption secret.
             * @param secret secret informations to use during the encryption of
             * the code.
             */
            template <std::uint8_t word_size = kByteWordSize>
            void
            encrypt_code(const EncryptionSecret<word_size> &secret) noexcept;

            /**
             * Generate the raw bytes that correspond to the decryption
             * procedure.
             * @param base_va virtual address where the first instruction of
             * this procedure will be placed.
             * @param jump_va virtual address where to jump after finishing the
             * execution of the decryption procedure.
             * @return the final raw code ready to be stored (or directly used).
             */
            RawCode produce_raw(Address base_va, Address jump_va) noexcept;

          protected:
            BinaryEditor<Editor> &editor_;
            asmjit::CodeHolder code_holder_;
            std::unique_ptr<Compiler> compiler_;

          private:
            static_assert(std::is_base_of<BinaryEditor<Editor>, Editor>::value,
                          "The template parameter Editor must implement "
                          "BinaryEditor interface.");

            static_assert(std::is_base_of<poly::Compiler, Compiler>::value,
                          "The template parameter Compiler must inherit from "
                          "poly::Compiler.");

            /**
             * Structure needed to access the protected methods implemented by
             * the final concrete class.
             */
            struct ProtectedAccessor : public Real {
                static void generate_syscall(Real &real, Address code_va,
                                             std::size_t len,
                                             asmjit::Label &exit_label);
            };

            /**
             * Structure needed to transform the final ret instruction
             * automatically generated from Compiler into a jmp instruction.
             */
            struct RetToJmpPass : public asmjit::Pass {
                /**
                 * @param va virtual address where to jump.
                 */
                RetToJmpPass(std::uint64_t va);

                asmjit::Error run(asmjit::Zone *zone, asmjit::Logger *logger);

              private:
                std::uint64_t va_;
            };
        };

        /**
         * Generic implementation for not supported operating systems. In order
         * to support an os, a specialization for the appropriate HostOS value
         * must be provided.
         */
        template <class Cipher, class Compiler, class Editor,
                  HostOS OS = HostOS::kNotSupported>
        class PolymorphicEngine
            : public impl::PolymorphicEngineBase<
                  PolymorphicEngine<Cipher, Compiler, Editor, OS>, Cipher,
                  Compiler, Editor> {
            static_assert(OS != HostOS::kNotSupported, "");
        };

    } // namespace impl

    /**
     * This class deals with the encryption of the binary's text section
     * and the generation of the correspondent code for the decryption
     * procedure.
     * This class can be customized with its template parameters:
     * - the Cipher class template parameter is used for the encryption and
     * decryption. It must provide the following static methods:
     *      template <std::uint8_t size>
     *      Error Cipher::assemble_decryption(EncryptionSecret<word_size> &,
     *          Compiler &, Register &, std::size_t, asmjit::Label &)
     *      template <std::uint8_t size>
     *      Error Cipher::encrypt(RawCode &, EncryptionSecret<word_size> &)
     * - the Compiler class template parameter is used for the generation of the
     * assembly code and its serialization. It must inherit from poly::Compiler
     * - the Editor class template parameter is used for the querying and
     * modifications of the binary. It must inherit from BinaryEditor<Editor>
     * and implement all its required metods. On Windows Editor must also
     * provide the following method:
     *      Address Editor::get_imported_function_va(const std::string &,
     *                  const std::string &)
     * On MacOS Editor must also provide the following methods:
     *      std::uint8_t Editor::code_max_permissions()
     *      std::uint8_t Editor::code_max_permissions(std::uint8_t)
     */
    template <class Cipher, class Compiler = poly::Compiler,
              class Editor = OsBinaryEditor>
    using PolymorphicEngine =
        impl::PolymorphicEngine<Cipher, Compiler, Editor, kOS>;

} // namespace poly

#include "engine.tpp"