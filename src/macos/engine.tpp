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
            auto syscall_code = this->compiler_->newUInt64();
            auto first_arg = this->compiler_->newUIntPtr();
            auto second_arg = this->compiler_->newUInt64();
            auto third_arg = this->compiler_->newUInt32();

            auto fixed_len = len;
            asmjit::x86::Mem fixed_va(
                this->editor_.align_to_page_size(code_va, fixed_len));

            // set the address to be encoded as relative
            fixed_va.setRel();

            // on macos the bsd syscall convention is used
            constexpr auto kMprotectCode = 74;

            // on macos 0x2000000 has to be added to every syscall code
            this->compiler_->xor_(syscall_code, syscall_code);
            this->compiler_->add(syscall_code, kMprotectCode + 0x2000000);

            // put in the first_arg the address of the code contained in
            // fixed_va
            this->compiler_->lea(first_arg, fixed_va);

            this->compiler_->xor_(second_arg, second_arg);
            this->compiler_->add(second_arg, fixed_len);

            this->compiler_->xor_(third_arg, third_arg);
            this->compiler_->add(third_arg, PROT_READ | PROT_WRITE | PROT_EXEC);

            // the signature is: int mprotect(void *addr, size_t len, int
            // prot), and we add an extra first argument which represent the
            // system call code to use
            asmjit::InvokeNode *invoke;
            this->compiler_->addInvokeNode(
                &invoke, asmjit::x86::Inst::kIdSyscall, asmjit::Globals::none,
                asmjit::FuncSignatureT<int, std::size_t, void *, std::size_t,
                                       int>());

            // shift the registers used to pass the parameters by one
            // position and set the first register to use to zax
            auto *args = invoke->detail().argPacks();
            std::uint32_t old;
            for (auto i = 0; i < invoke->argCount(); i++) {
                if (i == 0) {
                    old = args[i][0].regId();
                    args[i][0].setRegId(asmjit::x86::Gp::Id::kIdAx);
                } else {
                    auto tmp = old;
                    old = args[i][0].regId();
                    args[i][0].setRegId(tmp);
                }
            }

            invoke->setArg(0, syscall_code);
            invoke->setArg(1, first_arg);
            invoke->setArg(2, second_arg);
            invoke->setArg(3, third_arg);

            // if there was an error with mprotect exit NOW!
            // in macos the result value contained in rax is an error only
            // if the carry bit is set
            this->compiler_->jc(exit_label);
        }

    } // namespace impl

} // namespace poly