#pragma once

#include <cstdint>

#include <memory>
#include <string>
#include <vector>

#include <LIEF/LIEF.hpp>

#include "poly/binary_editor.hpp"
#include "poly/enums.hpp"
#include "poly/host_properties.hpp"
#include "poly/utils.hpp"

namespace poly {

    namespace impl {

        template <>
        struct Binary<HostOS::kMacOS> : LIEF::MachO::Binary {};

        template <>
        struct Section<HostOS::kMacOS> : LIEF::MachO::Section {};

        extern "C" Address get_entry_point_ra() noexcept;

        /**
         * Concrete implementation of BinaryEditor specific for MachO binaries.
         */
        template <>
        class CustomBinaryEditor<HostOS::kMacOS>
            : public CommonBinaryEditor<CustomBinaryEditor<HostOS::kMacOS>> {
          public:
            static std::unique_ptr<
                BinaryEditor<CustomBinaryEditor<HostOS::kMacOS>>>
            build(const std::string &path) noexcept;

            static std::unique_ptr<
                BinaryEditor<CustomBinaryEditor<HostOS::kMacOS>>>
            build(const std::vector<std::uint8_t> &raw,
                  const std::string &name) noexcept;

            static inline std::unique_ptr<
                BinaryEditor<CustomBinaryEditor<HostOS::kMacOS>>>
            build(std::istream &src, std::size_t size,
                  const std::string &name) noexcept {
                return CommonBinaryEditor<
                    CustomBinaryEditor<HostOS::kMacOS>>::build(src, size, name);
            }

            Address first_execution_va() const noexcept;

            Address exec_first(Address va) noexcept;

            Error inject_section(const std::string &name,
                                 const RawCode &content) noexcept;

            /**
             * Get the max permissions that can be setted for executable code.
             * @return a value which contains the combination of permissions.
             * The values associated are:
             * - read: 0x4
             * - write: 0x2
             * - exec: 0x1
             */
            inline std::uint8_t code_max_permissions() const noexcept {
                return static_cast<std::uint8_t>(
                    this->text_section_.segment()->max_protection());
            }

            /**
             * Change the max permissions that can be setted for executable
             * code.
             * @param perms new permissions to set. If the passed parameter uses
             * other bits besides the first 3, their value will be ignored.
             * @return the old permissions.
             */
            std::uint8_t code_max_permissions(std::uint8_t perms) noexcept;

          protected:
            CustomBinaryEditor(std::unique_ptr<LIEF::MachO::Binary> &&bin,
                               LIEF::MachO::Section &text_section) noexcept;

            inline bool
            has_section_impl(const std::string &name) const noexcept {
                return this->bin_->get_section(kSectionPrefix_ + name) !=
                       nullptr;
            }

            inline Section<HostOS::kMacOS> *
            get_section_impl(const std::string &name) noexcept {
                return static_cast<Section<HostOS::kMacOS> *>(
                    this->bin_->get_section(kSectionPrefix_ + name));
            }
            inline const Section<HostOS::kMacOS> *
            get_section_impl(const std::string &name) const noexcept {
                return static_cast<Section<HostOS::kMacOS> *>(
                    this->bin_->get_section(kSectionPrefix_ + name));
            }

            inline Section<HostOS::kMacOS> &get_text_section_impl() noexcept {
                return static_cast<Section<HostOS::kMacOS> &>(
                    this->text_section_);
            }
            inline const Section<HostOS::kMacOS> &
            get_text_section_impl() const noexcept {
                return static_cast<Section<HostOS::kMacOS> &>(
                    this->text_section_);
            }

            inline Binary<HostOS::kMacOS> &get_bin_impl() noexcept {
                return static_cast<Binary<HostOS::kMacOS> &>(*this->bin_);
            }
            inline const Binary<HostOS::kMacOS> &get_bin_impl() const noexcept {
                return static_cast<Binary<HostOS::kMacOS> &>(*this->bin_);
            }

            inline Address get_entry_point_ra_impl() const noexcept {
                return impl::get_entry_point_ra();
            }

            static constexpr Address kPageSize_ = 4096;
            static const std::string kSectionPrefix_;

          private:
            /**
             * Check if the binary passed is a valid one, and if it is create a
             * new CustomBinaryEditor<HostOS::kMacOS>.
             */
            static std::unique_ptr<
                BinaryEditor<CustomBinaryEditor<HostOS::kMacOS>>>
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

            std::unique_ptr<LIEF::MachO::Binary> bin_;
            LIEF::MachO::Section &text_section_;
        };

    } // namespace impl

} // namespace poly