#pragma once

#include <cstdint>

#include <memory>
#include <vector>

#include <asmjit/asmjit.h>

#include "poly/binary_editor.hpp"
#include "poly/encryption.hpp"
#include "poly/engine.hpp"
#include "poly/enums.hpp"
#include "poly/host_properties.hpp"
#include "poly/utils.hpp"

namespace poly {

    namespace impl {

        template <class Real, class Cipher, class Compiler, class Editor>
        PolymorphicEngineBase<Real, Cipher, Compiler, Editor>::RetToJmpPass::
            RetToJmpPass(std::uint64_t va)
            : asmjit::Pass{"RetToJmpPass"}, va_{va} {}

        template <class Real, class Cipher, class Compiler, class Editor>
        asmjit::Error PolymorphicEngineBase<Real, Cipher, Compiler, Editor>::
            RetToJmpPass::run(asmjit::Zone *zone, asmjit::Logger *logger) {
            asmjit::InstNode *return_inst = nullptr;
            auto *n = this->_cb->lastNode();
            while (return_inst == nullptr) {
                if (n->isInst()) {
                    return_inst = n->template as<asmjit::InstNode>();
                    if (return_inst->id() != asmjit::x86::Inst::kIdRet) {
                        return_inst = nullptr;
                    }
                } else if (n == this->_cb->firstNode()) {
                    return asmjit::kErrorOk;
                } else {
                    n = n->prev();
                }
            }

            return_inst->setId(asmjit::x86::Inst::kIdJmp);
            return_inst->setOp(0, asmjit::Imm(this->va_));

            return asmjit::kErrorOk;
        }

        template <class Real, class Cipher, class Compiler, class Editor>
        PolymorphicEngineBase<Real, Cipher, Compiler, Editor>::
            PolymorphicEngineBase(BinaryEditor<Editor> &editor,
                                  std::unique_ptr<Compiler> compiler) noexcept
            : editor_{editor}, code_holder_{}, compiler_{compiler.release()} {

            if (this->compiler_ == nullptr) {
                this->compiler_ = std::make_unique<Compiler>();
            }

            this->code_holder_.init(asmjit::Environment::host());
            this->code_holder_.attach(this->compiler_.get());
        }

        template <class Real, class Cipher, class Compiler, class Editor>
        template <std::uint8_t word_size>
        void
        PolymorphicEngineBase<Real, Cipher, Compiler, Editor>::generate_code(
            const EncryptionSecret<word_size> &secret) {

            static_assert(
                impl::supports_decryption<Cipher, EncryptionSecret<word_size> &,
                                          Compiler &, Register &, std::size_t,
                                          asmjit::Label &>::value,
                "Cipher template parameter must implement this static method: "
                "template <std::uint8_t size> Error "
                "assemble_decryption(EncryptionSecret<word_size> &, Compiler "
                "&, "
                "Register &, std::size_t, asmjit::Label &)");

            this->compiler_->addFunc(asmjit::FuncSignatureT<void>());
            auto exit_label = this->compiler_->newLabel();

            ProtectedAccessor::generate_syscall(
                *this->real(), this->editor_.text_section_va(),
                this->editor_.text_section_size(), exit_label);

            auto start_reg = this->compiler_->newUInt64();
            asmjit::x86::Mem code_va(this->editor_.text_section_va());
            code_va.setRel();
            this->compiler_->lea(start_reg, code_va);

            auto decryption_err = Cipher::assemble_decryption(
                secret, *this->compiler_, start_reg,
                this->editor_.text_section_size(), exit_label);

            this->compiler_->bind(exit_label);
            this->compiler_->endFunc();
        }

        template <class Real, class Cipher, class Compiler, class Editor>
        template <std::uint8_t word_size>
        void
        PolymorphicEngineBase<Real, Cipher, Compiler, Editor>::encrypt_code(
            const EncryptionSecret<word_size> &secret) noexcept {

            static_assert(
                impl::supports_encryption<Cipher, RawCode &,
                                          EncryptionSecret<word_size> &>::value,
                "Cipher template parameter must implement this static method: "
                "template <std::uint8_t size> Error "
                "encrypt(RawCode &, EncryptionSecret<word_size> &)");

            RawCode decrypted_code(reinterpret_cast<std::uint8_t *>(
                                       this->editor_.text_section_ra()),
                                   this->editor_.text_section_size());
            std::vector<std::uint8_t> new_code(decrypted_code.size());

            RawCode result_code{new_code.data(), new_code.size()};
            Cipher::encrypt(decrypted_code, result_code, secret);

            this->editor_.update_text_section_content(result_code);
        }

        template <class Real, class Cipher, class Compiler, class Editor>
        RawCode
        PolymorphicEngineBase<Real, Cipher, Compiler, Editor>::produce_raw(
            Address base_va, Address jump_va) noexcept {
            this->compiler_->template addPassT<RetToJmpPass>(jump_va);

            this->compiler_->finalize();
            this->code_holder_.flatten();
            this->code_holder_.resolveUnresolvedLinks();
            this->code_holder_.relocateToBase(base_va);

            auto *code_section = this->code_holder_.textSection();
            return RawCode{code_section->data(), code_section->realSize()};
        }

        template <class Real, class Cipher, class Compiler, class Editor>
        inline void PolymorphicEngineBase<Real, Cipher, Compiler, Editor>::
            ProtectedAccessor::generate_syscall(Real &real, Address code_va,
                                                std::size_t len,
                                                asmjit::Label &exit_label) {
            (real.*(&ProtectedAccessor::generate_syscall_impl))(code_va, len,
                                                                exit_label);
        }

    } // namespace impl

} // namespace poly

#if defined(POLY_LINUX)
#include "linux/engine.tpp"
#elif defined(POLY_MACOS)
#include "macos/engine.tpp"
#elif defined(POLY_WINDOWS)
#include "windows/engine.tpp"
#endif