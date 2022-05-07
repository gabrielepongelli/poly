#pragma once

#include <sys/mman.h>

#include <asmjit/asmjit.h>

#include "poly/engine.hpp"
#include "poly/enums.hpp"
#include "poly/linux/engine.hpp"
#include "poly/utils.hpp"

namespace poly {

    namespace impl {

        template <class Cipher, class Compiler, class Editor>
        PolymorphicEngine<Cipher, Compiler, Editor, HostOS::kLinux>::
            PolymorphicEngine(BinaryEditor<Editor> &editor,
                              std::unique_ptr<Compiler> compiler) noexcept
            : PolymorphicEngineBase<
                  PolymorphicEngine<Cipher, Compiler, Editor, HostOS::kLinux>,
                  Cipher, Compiler, Editor>(editor, std::move(compiler)) {}

        template <class Cipher, class Compiler, class Editor>
        void PolymorphicEngine<Cipher, Compiler, Editor, HostOS::kLinux>::
            generate_syscall_impl(Address code_va, std::size_t len,
                                  asmjit::Label &exit_label) {

            auto syscall_code = this->compiler_->zax();
            auto start_address = this->compiler_->zdi();
            auto fixed_len = len;
            asmjit::x86::Mem fixed_va(
                this->editor_.align_to_page_size(code_va, fixed_len));

            // set the address to be encoded as relative
            fixed_va.setRel();

            constexpr auto kMprotectCode = 10;
            this->compiler_->mov(syscall_code, kMprotectCode);
            this->compiler_->lea(start_address, fixed_va);

            // the signature is: int mprotect(void *addr, size_t len, int
            // prot)
            asmjit::InvokeNode *invoke;
            this->compiler_->addInvokeNode(
                &invoke, asmjit::x86::Inst::kIdSyscall, asmjit::Globals::none,
                asmjit::FuncSignatureT<int, void *, std::size_t, int>());

            invoke->setArg(1, fixed_len);
            invoke->setArg(2, PROT_READ | PROT_WRITE | PROT_EXEC);

            auto syscall_result = this->compiler_->zax();

            // if there was an error with mprotect exit NOW!
            this->compiler_->cmp(syscall_result, 0);
            this->compiler_->jne(exit_label);
        }

    } // namespace impl

} // namespace poly