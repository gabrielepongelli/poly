#pragma once

#include <cstdint>

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
        struct Binary<HostOS::kMacOS> : LIEF::MachO::Binary {};

        template <>
        struct Section<HostOS::kMacOS> : LIEF::MachO::Section {};

        extern "C" Address get_entry_point_ra() noexcept;

    } // namespace impl

    //!
    //! Concrete implementation of BinaryEditor specific for MachO binaries.
    //!
    //! \see poly::OsBinaryEditor
    //! \see poly::BinaryEditor<Real>
    //!
    template <>
    class CustomBinaryEditor<HostOS::kMacOS>
        : public CommonBinaryEditor<CustomBinaryEditor<HostOS::kMacOS>> {
      public:
        static std::unique_ptr<BinaryEditor<CustomBinaryEditor<HostOS::kMacOS>>>
        build(const fs::path &path) noexcept;

        static std::unique_ptr<BinaryEditor<CustomBinaryEditor<HostOS::kMacOS>>>
        build(const std::vector<std::uint8_t> &raw,
              const fs::path &path) noexcept;

        static inline std::unique_ptr<
            BinaryEditor<CustomBinaryEditor<HostOS::kMacOS>>>
        build(std::istream &src, std::size_t size,
              const fs::path &path) noexcept {
            return CommonBinaryEditor<
                CustomBinaryEditor<HostOS::kMacOS>>::build(src, size, path);
        }

        Address first_execution_va() const noexcept;

        Address exec_first(Address va) noexcept;

        Error inject_section(const std::string &name,
                             const RawCode &content) noexcept;

        Error update_content(const std::string &name,
                             const RawCode &content) noexcept;

        //!
        //! Get the max permissions that can be setted for executable code.
        //! \return a value which contains the combination of permissions.
        //! The values associated are:
        //! - read: 0x4
        //! - write: 0x2
        //! - exec: 0x1
        //!
        inline std::uint8_t code_max_permissions() const noexcept {
            return static_cast<std::uint8_t>(
                this->text_section_.segment()->max_protection());
        }

        //!
        //! Change the max permissions that can be setted for executable
        //! code.
        //! \param perms new permissions to set. If the passed parameter uses
        //! other bits besides the first 3, their value will be ignored.
        //! \return the old permissions.
        //!
        std::uint8_t code_max_permissions(std::uint8_t perms) noexcept;

        bool save_changes(const fs::path &path) noexcept;

        inline bool save_changes(std::vector<std::uint8_t> &raw) noexcept {
            raw = std::move(this->bin_->raw());
            return false;
        }

        inline bool save_changes(std::ostream &dst) noexcept {
            return CommonBinaryEditor<
                CustomBinaryEditor<HostOS::kMacOS>>::save_changes(dst);
        }

      protected:
        //!
        //! \private
        //! \internal
        //! \protected
        //!
        //! \see poly::CommonBinaryEditor<Real>::ProtectedAccessor
        //!
        CustomBinaryEditor(std::unique_ptr<LIEF::MachO::Binary> &&bin,
                           LIEF::MachO::Section &text_section) noexcept;

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
        inline impl::Section<HostOS::kMacOS> *
        get_section_impl(const std::string &name) noexcept {
            return static_cast<impl::Section<HostOS::kMacOS> *>(
                this->bin_->get_section(kSectionPrefix_ + name));
        }

        //!
        //! \private
        //! \internal
        //! \protected
        //!
        //! \see poly::CommonBinaryEditor<Real>::ProtectedAccessor
        //!
        inline const impl::Section<HostOS::kMacOS> *
        get_section_impl(const std::string &name) const noexcept {
            return static_cast<impl::Section<HostOS::kMacOS> *>(
                this->bin_->get_section(kSectionPrefix_ + name));
        }

        //!
        //! \private
        //! \internal
        //! \protected
        //!
        //! \see poly::CommonBinaryEditor<Real>::ProtectedAccessor
        //!
        inline impl::Section<HostOS::kMacOS> &get_text_section_impl() noexcept {
            return static_cast<impl::Section<HostOS::kMacOS> &>(
                this->text_section_);
        }

        //!
        //! \private
        //! \internal
        //! \protected
        //!
        //! \see poly::CommonBinaryEditor<Real>::ProtectedAccessor
        //!
        inline const impl::Section<HostOS::kMacOS> &
        get_text_section_impl() const noexcept {
            return static_cast<impl::Section<HostOS::kMacOS> &>(
                this->text_section_);
        }

        //!
        //! \private
        //! \internal
        //! \protected
        //!
        //! \see poly::CommonBinaryEditor<Real>::ProtectedAccessor
        //!
        inline impl::Binary<HostOS::kMacOS> &get_bin_impl() noexcept {
            return static_cast<impl::Binary<HostOS::kMacOS> &>(*this->bin_);
        }

        //!
        //! \private
        //! \internal
        //! \protected
        //!
        //! \see poly::CommonBinaryEditor<Real>::ProtectedAccessor
        //!
        inline const impl::Binary<HostOS::kMacOS> &
        get_bin_impl() const noexcept {
            return static_cast<impl::Binary<HostOS::kMacOS> &>(*this->bin_);
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
        //! new CustomBinaryEditor<HostOS::kMacOS>.
        //!
        static std::unique_ptr<BinaryEditor<CustomBinaryEditor<HostOS::kMacOS>>>
        check_and_init(std::unique_ptr<LIEF::MachO::Binary> &&bin);

        /**
         * Check whether the binary has section for global initializers
         * with at least one initializer address.
         */
        bool has_global_init() const noexcept;

        /**
         * Retrieve the virtual address of the first global initializer
         * executed by the binary. If it hasn't any initializer, the
         * returned value is 0.
         */
        Address first_global_init() const noexcept;

        /**
         * Overwrite the virtual address of the first global initializer of
         * the binary with the one specified.
         * @param va new virtual address.
         * @return kNone if no error is raised.
         */
        Error first_global_init(Address va) noexcept;

        static const std::string kNewSegmentName_;
        static constexpr std::size_t kSegmentMinSize_ = 0x4000;

        std::unique_ptr<LIEF::MachO::Binary> bin_;
        LIEF::MachO::Section &text_section_;
    };

} // namespace poly