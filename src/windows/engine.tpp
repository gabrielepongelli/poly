#pragma once

#include <Windows.h>

#include <asmjit/asmjit.h>

#include "poly/engine.hpp"
#include "poly/enums.hpp"
#include "poly/utils.hpp"
#include "poly/windows/engine.hpp"

namespace poly {

    namespace impl {

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

            auto start_address = this->compiler_->zcx();
            auto old_page_ptr = this->compiler_->newIntPtr();
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

            this->compiler_->lea(start_address, mem_va);
            this->compiler_->lea(old_page_ptr, old_page_perms);

            // the signature is: BOOL VirtualProtect(LPVOID lpAddress,
            // SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect)
            asmjit::InvokeNode *invoke;
            this->compiler_->invoke(
                &invoke, virtualprotect_va,
                asmjit::FuncSignatureT<BOOL, LPVOID, SIZE_T, DWORD, PDWORD>());

            invoke->setArg(1, fixed_len);
            invoke->setArg(2, PAGE_EXECUTE_READWRITE);
            invoke->setArg(3, old_page_ptr);

            auto virtualprotect_result = this->compiler_->zax();

            // if there was an error with virtualprotect exit NOW!
            this->compiler_->cmp(virtualprotect_result, 0);
            this->compiler_->je(exit_label);
        }

    } // namespace impl

} // namespace poly