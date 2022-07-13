#pragma once

#include <Windows.h>

#include <asmjit/asmjit.h>

#include "poly/engine.hpp"
#include "poly/enums.hpp"
#include "poly/utils.hpp"
#include "poly/windows/engine.hpp"

namespace poly {

    template <class Cipher, class Compiler, class Editor>
    PolymorphicEngine<Cipher, Compiler, Editor, HostOS::kWindows>::
        PolymorphicEngine(BinaryEditor<Editor> &editor,
                          std::unique_ptr<Compiler> compiler) noexcept
        : PolymorphicEngineBase<
              PolymorphicEngine<Cipher, Compiler, Editor, HostOS::kWindows>,
              Cipher, Compiler, Editor>(editor, std::move(compiler)) {}

    template <class Cipher, class Compiler, class Editor>
    void PolymorphicEngine<Cipher, Compiler, Editor, HostOS::kWindows>::
        generate_syscall_impl(Address code_va, std::size_t len,
                              asmjit::Label &exit_label) {
        auto first_arg = this->compiler_->newUInt64();
        auto second_arg = this->compiler_->newUInt64();
        auto third_arg = this->compiler_->newUInt64();
        auto fourth_arg = this->compiler_->newIntPtr();
        auto old_page_perms =
            this->compiler_->newStack(kByteWordSize, kByteWordSize);
        auto fixed_len = len;
        asmjit::x86::Mem mem_va(code_va);

        // set the address to be encoded as relative
        mem_va.setRel();

        // mandatory line that use the VirtualProtect function so that it
        // can be added to the imported functions automatically during the
        // linking. This call will certainly fail because the 4th argument
        // is nullptr.
        VirtualProtect(0, 0, 0, nullptr);

        auto &windows_editor = static_cast<OsBinaryEditor &>(this->editor_);
        asmjit::x86::Mem virtualprotect_va(
            windows_editor.get_imported_function_va("KERNEL32.dll",
                                                    "VirtualProtect"));
        virtualprotect_va.setRel();

        this->compiler_->lea(first_arg, mem_va);

        this->compiler_->xor_(second_arg, second_arg);
        this->compiler_->add(second_arg, fixed_len);

        this->compiler_->xor_(third_arg, third_arg);
        this->compiler_->add(third_arg, PAGE_EXECUTE_READWRITE);

        this->compiler_->lea(fourth_arg, old_page_perms);

        // the signature is: BOOL VirtualProtect(LPVOID lpAddress,
        // SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect)
        asmjit::InvokeNode *invoke;
        this->compiler_->invoke(
            &invoke, virtualprotect_va,
            asmjit::FuncSignatureT<BOOL, LPVOID, SIZE_T, DWORD, PDWORD>());

        invoke->setArg(0, first_arg);
        invoke->setArg(1, second_arg);
        invoke->setArg(2, third_arg);
        invoke->setArg(3, fourth_arg);

        auto virtualprotect_result = this->compiler_->zax();

        // if there was an error with virtualprotect exit NOW!
        this->compiler_->cmp(virtualprotect_result, 0);
        this->compiler_->je(exit_label);
    }

} // namespace poly