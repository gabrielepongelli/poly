#pragma once

#include <memory>

#include <asmjit/asmjit.h>

#include "poly/binary_editor.hpp"
#include "poly/engine.hpp"
#include "poly/enums.hpp"
#include "poly/utils.hpp"

namespace poly {

    //!
    //! Concrete implementation of PolymorphicEngineBase specific for Linux.
    //!
    //! \see poly::PolymorphicEngineBase
    //! \see poly::PolymorphicEngine
    //! \see poly::PolymorphicEngine<Cipher, Compiler, Editor, HostOS::kMacOS>
    //! \see poly::PolymorphicEngine<Cipher, Compiler, Editor, HostOS::kWindows>
    //! \see poly::OsPolymorphicEngine<Cipher, Compiler, Editor>
    //!
    template <class Cipher, class Compiler, class Editor>
    class PolymorphicEngine<Cipher, Compiler, Editor, HostOS::kLinux>
        : public PolymorphicEngineBase<
              PolymorphicEngine<Cipher, Compiler, Editor, HostOS::kLinux>,
              Cipher, Compiler, Editor> {
      public:
        PolymorphicEngine(
            BinaryEditor<Editor> &editor,
            std::unique_ptr<Compiler> compiler = nullptr) noexcept;

      protected:
        //!
        //! \private
        //! \internal
        //! \protected
        //!
        //! \see poly::PolymorphicEngineBase<Real, Cipher, Compiler,
        //! Editor>::ProtectedAccessor
        //!
        void generate_syscall_impl(Address code_va, std::size_t len,
                                   asmjit::Label &exit_label);
    };

} // namespace poly