#pragma once

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include <LIEF/LIEF.hpp>

#include "poly/binary_editor.hpp"
#include "poly/enums.hpp"
#include "poly/filesystem.hpp"
#include "poly/host_properties.hpp"
#include "poly/utils.hpp"

namespace poly {

    namespace impl {

        template <>
        struct Binary<HostOS::kLinux> : LIEF::ELF::Binary {};

        template <>
        struct Section<HostOS::kLinux> : LIEF::ELF::Section {};

        extern "C" Address get_entry_point_ra() noexcept;

    } // namespace impl

    //!
    //! Concrete implementation of BinaryEditor specific for ELF binaries.
    //!
    //! \see poly::OsBinaryEditor
    //! \see poly::BinaryEditor<Real>
    //!
    template <>
    class CustomBinaryEditor<HostOS::kLinux>
        : public CommonBinaryEditor<CustomBinaryEditor<HostOS::kLinux>> {
      public:
        static std::unique_ptr<BinaryEditor<CustomBinaryEditor<HostOS::kLinux>>>
        build(const fs::path &path) noexcept;

        static std::unique_ptr<BinaryEditor<CustomBinaryEditor<HostOS::kLinux>>>
        build(const std::vector<std::uint8_t> &raw,
              const fs::path &path) noexcept;

        static inline std::unique_ptr<
            BinaryEditor<CustomBinaryEditor<HostOS::kLinux>>>
        build(std::istream &src, std::size_t size,
              const fs::path &path) noexcept {
            return CommonBinaryEditor<
                CustomBinaryEditor<HostOS::kLinux>>::build(src, size, path);
        }

        inline Address first_execution_va() const noexcept {
            return this->bin_->entrypoint();
        }

        Address exec_first(Address va) noexcept;

        Error inject_section(const std::string &name,
                             const RawCode &content) noexcept;

        Error update_content(const std::string &name,
                             const RawCode &content) noexcept;

        bool save_changes(const fs::path &path) noexcept;

        inline bool save_changes(std::vector<std::uint8_t> &raw) noexcept {
            raw = std::move(this->bin_->raw());
            return true;
        }

        inline bool save_changes(std::ostream &dst) noexcept {
            return CommonBinaryEditor<
                CustomBinaryEditor<HostOS::kLinux>>::save_changes(dst);
        }

      protected:
        //!
        //! \private
        //! \internal
        //! \protected
        //!
        //! \see poly::CommonBinaryEditor<Real>::ProtectedAccessor
        //!
        CustomBinaryEditor(std::unique_ptr<LIEF::ELF::Binary> &&bin,
                           LIEF::ELF::Section &text_section) noexcept;

        //!
        //! \private
        //! \internal
        //! \protected
        //!
        //! \see poly::CommonBinaryEditor<Real>::ProtectedAccessor
        //!
        inline bool has_section_impl(const std::string &name) const noexcept {
            return this->bin_->get_section(kSectionPrefix_ + name) != nullptr;
        }

        //!
        //! \private
        //! \internal
        //! \protected
        //!
        //! \see poly::CommonBinaryEditor<Real>::ProtectedAccessor
        //!
        inline impl::Section<HostOS::kLinux> *
        get_section_impl(const std::string &name) noexcept {
            return static_cast<impl::Section<HostOS::kLinux> *>(
                this->bin_->get_section(kSectionPrefix_ + name));
        }

        //!
        //! \private
        //! \internal
        //! \protected
        //!
        //! \see poly::CommonBinaryEditor<Real>::ProtectedAccessor
        //!
        inline const impl::Section<HostOS::kLinux> *
        get_section_impl(const std::string &name) const noexcept {
            return static_cast<impl::Section<HostOS::kLinux> *>(
                this->bin_->get_section(kSectionPrefix_ + name));
        }

        //!
        //! \private
        //! \internal
        //! \protected
        //!
        //! \see poly::CommonBinaryEditor<Real>::ProtectedAccessor
        //!
        inline impl::Section<HostOS::kLinux> &get_text_section_impl() noexcept {
            return static_cast<impl::Section<HostOS::kLinux> &>(
                this->text_section_);
        }

        //!
        //! \private
        //! \internal
        //! \protected
        //!
        //! \see poly::CommonBinaryEditor<Real>::ProtectedAccessor
        //!
        inline const impl::Section<HostOS::kLinux> &
        get_text_section_impl() const noexcept {
            return static_cast<impl::Section<HostOS::kLinux> &>(
                this->text_section_);
        }

        //!
        //! \private
        //! \internal
        //! \protected
        //!
        //! \see poly::CommonBinaryEditor<Real>::ProtectedAccessor
        //!
        inline impl::Binary<HostOS::kLinux> &get_bin_impl() noexcept {
            return static_cast<impl::Binary<HostOS::kLinux> &>(*this->bin_);
        }

        //!
        //! \private
        //! \internal
        //! \protected
        //!
        //! \see poly::CommonBinaryEditor<Real>::ProtectedAccessor
        //!
        inline const impl::Binary<HostOS::kLinux> &
        get_bin_impl() const noexcept {
            return static_cast<impl::Binary<HostOS::kLinux> &>(*this->bin_);
        }

        //!
        //! \private
        //! \internal
        //! \protected
        //!
        //! \see poly::CommonBinaryEditor<Real>::ProtectedAccessor
        //!
        inline Address get_entry_point_ra_impl() const noexcept {
            return impl::get_entry_point_ra();
        }

        //!
        //! \private
        //! \internal
        //! \protected
        //!
        //! \see poly::CommonBinaryEditor<Real>::ProtectedAccessor
        //!
        static constexpr Address kPageSize_ = 4096;

        //!
        //! \private
        //! \internal
        //! \protected
        //!
        //! \see poly::CommonBinaryEditor<Real>::ProtectedAccessor
        //!
        static const std::string kSectionPrefix_;

      private:
        //!
        //! Check if the binary passed is a valid one, and if it is create a
        //! new CustomBinaryEditor<HostOS::kLinux>.
        //!
        static std::unique_ptr<BinaryEditor<CustomBinaryEditor<HostOS::kLinux>>>
        check_and_init(std::unique_ptr<LIEF::ELF::Binary> &&bin);

        std::unique_ptr<LIEF::ELF::Binary> bin_;
        LIEF::ELF::Section &text_section_;
    };

} // namespace poly