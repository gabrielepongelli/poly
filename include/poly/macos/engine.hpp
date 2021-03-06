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
        using code_max_permissions_getter_t = std::enable_if<
            std::is_same<decltype(std::declval<T>().code_max_permissions(
                             std::declval<Args>()...)),
                         std::uint8_t>::value,
            decltype(std::declval<T>().code_max_permissions(
                std::declval<Args>()...))>;

        template <class T, typename... Args>
        using supports_code_max_permissions_getter =
            is_detected_t<code_max_permissions_getter_t, T, Args...>;

        template <class T, typename... Args>
        using code_max_permissions_setter_t = std::enable_if<
            std::is_same<decltype(std::declval<T>().code_max_permissions(
                             std::declval<Args>()...)),
                         std::uint8_t>::value,
            decltype(std::declval<T>().code_max_permissions(
                std::declval<Args>()...))>;

        template <class T, typename... Args>
        using supports_code_max_permissions_setter =
            is_detected_t<code_max_permissions_setter_t, T, Args...>;

    } // namespace impl

    //!
    //! Concrete implementation of PolymorphicEngineBase specific for MacOS.
    //!
    //! \see poly::PolymorphicEngineBase
    //! \see poly::PolymorphicEngine
    //! \see poly::PolymorphicEngine<Cipher, Compiler, Editor, HostOS::kLinux>
    //! \see poly::PolymorphicEngine<Cipher, Compiler, Editor, HostOS::kWindows>
    //! \see poly::OsPolymorphicEngine<Cipher, Compiler, Editor>
    //!
    template <class Cipher, class Compiler, class Editor>
    class PolymorphicEngine<Cipher, Compiler, Editor, HostOS::kMacOS>
        : public PolymorphicEngineBase<
              PolymorphicEngine<Cipher, Compiler, Editor, HostOS::kMacOS>,
              Cipher, Compiler, Editor> {
      public:
        PolymorphicEngine(
            BinaryEditor<Editor> &editor,
            std::unique_ptr<Compiler> compiler = nullptr) noexcept;

      protected:
        static_assert(
            impl::supports_code_max_permissions_getter<Editor>::value,
            "On MacOS the template parameter Editor must implement this "
            "method: std::uint8_t code_max_permissions()");

        static_assert(
            impl::supports_code_max_permissions_setter<Editor>::value,
            "On MacOS the template parameter Editor must implement this "
            "method: std::uint8_t code_max_permissions(std::uint8_t)");

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