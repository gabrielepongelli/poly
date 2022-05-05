#pragma once

#include <cstdint>

#include <memory>
#include <string>
#include <vector>

#include <LIEF/LIEF.hpp>

#include "engine/binary_editor.hpp"
#include "engine/enums.hpp"
#include "engine/host_properties.hpp"
#include "engine/utils.hpp"

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

            static constexpr Address kPageSize = 4096;

          protected:
            CustomBinaryEditor(std::unique_ptr<LIEF::MachO::Binary> &&bin,
                               LIEF::MachO::Section &text_section) noexcept;

            inline bool
            has_section_impl(const std::string &name) const noexcept {
                return this->bin_->get_section(kSectionPrefix + name) !=
                       nullptr;
            }

            inline Section<HostOS::kMacOS> *
            get_section_impl(const std::string &name) noexcept {
                return static_cast<Section<HostOS::kMacOS> *>(
                    this->bin_->get_section(kSectionPrefix + name));
            }
            inline const Section<HostOS::kMacOS> *
            get_section_impl(const std::string &name) const noexcept {
                return static_cast<Section<HostOS::kMacOS> *>(
                    this->bin_->get_section(kSectionPrefix + name));
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

            static const std::string kSectionPrefix;
            std::unique_ptr<LIEF::MachO::Binary> bin_;
            LIEF::MachO::Section &text_section_;
        };

    } // namespace impl

} // namespace poly