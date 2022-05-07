#pragma once

#include <memory>

#include <asmjit/asmjit.h>

#include "poly/binary_editor.hpp"
#include "poly/engine.hpp"
#include "poly/enums.hpp"
#include "poly/utils.hpp"

namespace poly {

    namespace impl {

        /**
         * Concrete implementation of PolymorphicEngineBase specific for Linux.
         */
        template <class Cipher, class Compiler, class Editor>
        class PolymorphicEngine<Cipher, Compiler, Editor, HostOS::kLinux>
            : public impl::PolymorphicEngineBase<
                  PolymorphicEngine<Cipher, Compiler, Editor, HostOS::kLinux>,
                  Cipher, Compiler, Editor> {
          public:
            PolymorphicEngine(
                BinaryEditor<Editor> &editor,
                std::unique_ptr<Compiler> compiler = nullptr) noexcept;

          protected:
            void generate_syscall_impl(Address code_va, std::size_t len,
                                       asmjit::Label &exit_label);
        };

    } // namespace impl

} // namespace poly