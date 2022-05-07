#pragma once

#include <sys/mman.h>

#include <memory>

#include <asmjit/asmjit.h>

#include "poly/engine.hpp"
#include "poly/enums.hpp"
#include "poly/macos/engine.hpp"
#include "poly/utils.hpp"

namespace poly {

    namespace impl {

        template <class Cipher, class Compiler, class Editor>
        PolymorphicEngine<Cipher, Compiler, Editor, HostOS::kMacOS>::
            PolymorphicEngine(BinaryEditor<Editor> &editor,
                              std::unique_ptr<Compiler> compiler) noexcept
            : PolymorphicEngineBase<
                  PolymorphicEngine<Cipher, Compiler, Editor, HostOS::kMacOS>,
                  Cipher, Compiler, Editor>(editor, std::move(compiler)) {
            auto &real_editor = static_cast<Editor &>(this->editor_);
            constexpr std::uint8_t kWrite = 0x2;

            auto perms = real_editor.code_max_permissions();
            if ((perms & kWrite) == 0) {
                real_editor.code_max_permissions(perms | kWrite);
            }
        }

        template <class Cipher, class Compiler, class Editor>
        void PolymorphicEngine<Cipher, Compiler, Editor, HostOS::kMacOS>::
            generate_syscall_impl(Address code_va, std::size_t len,
                                  asmjit::Label &exit_label) {

            auto syscall_code = this->compiler_->zax();
            auto start_address = this->compiler_->zdi();
            auto fixed_len = len;
            asmjit::x86::Mem fixed_va(
                this->editor_.align_to_page_size(code_va, fixed_len));

            // set the address to be encoded as relative
            fixed_va.setRel();

            // on macos the bsd syscall convention is used
            constexpr auto kMprotectCode = 74;

            // on macos 0x2000000 has to be added to every syscall code
            this->compiler_->mov(syscall_code, kMprotectCode + 0x2000000);

            // put in start_address the address of the code contained in
            // fixed_va
            this->compiler_->lea(start_address, fixed_va);

            // the signature is: int mprotect(void *addr, size_t len, int
            // prot)
            asmjit::InvokeNode *invoke;
            this->compiler_->addInvokeNode(
                &invoke, asmjit::x86::Inst::kIdSyscall, asmjit::Globals::none,
                asmjit::FuncSignatureT<int, void *, std::size_t, int>());

            invoke->setArg(1, fixed_len);
            invoke->setArg(2, PROT_READ | PROT_WRITE | PROT_EXEC);

            // if there was an error with mprotect exit NOW!
            // in macos the result value contained in rax is an error only
            // if the carry bit is set
            this->compiler_->jc(exit_label);
        }

    } // namespace impl

} // namespace poly