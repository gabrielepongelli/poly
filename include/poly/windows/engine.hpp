#pragma once

#include <memory>

#include <asmjit/asmjit.h>

#include "poly/binary_editor.hpp"
#include "poly/engine.hpp"
#include "poly/enums.hpp"
#include "poly/utils.hpp"

namespace poly {

    namespace impl {

        template <class T, typename... Args>
        using imported_function_va_getter_t = std::enable_if<
            std::is_same<decltype(std::declval<T>().get_imported_function_va(
                             std::declval<Args>()...)),
                         Address>::value,
            decltype(std::declval<T>().get_imported_function_va(
                std::declval<Args>()...))>;

        template <class T, typename... Args>
        using supports_imported_function_va_getter =
            is_detected_t<imported_function_va_getter_t, T, Args...>;

    } // namespace impl

    //!
    //! Concrete implementation of PolymorphicEngineBase specific for
    //! Windows.
    //!
    //! \see poly::PolymorphicEngineBase
    //! \see poly::PolymorphicEngine
    //! \see poly::PolymorphicEngine<Cipher, Compiler, Editor, HostOS::kLinux>
    //! \see poly::PolymorphicEngine<Cipher, Compiler, Editor, HostOS::kMacOS>
    //! \see poly::OsPolymorphicEngine<Cipher, Compiler, Editor>
    //!
    template <class Cipher, class Compiler, class Editor>
    class PolymorphicEngine<Cipher, Compiler, Editor, HostOS::kWindows>
        : public PolymorphicEngineBase<
              PolymorphicEngine<Cipher, Compiler, Editor, HostOS::kWindows>,
              Cipher, Compiler, Editor> {
      public:
        PolymorphicEngine(
            BinaryEditor<Editor> &editor,
            std::unique_ptr<Compiler> compiler = nullptr) noexcept;

      protected:
        static_assert(
            impl::supports_imported_function_va_getter<
                Editor, const std::string &, const std::string &>::value,
            "On Windows the template parameter Editor must implement this "
            "method: Address get_imported_function_va(const std::string &, "
            "const std::string &)");

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