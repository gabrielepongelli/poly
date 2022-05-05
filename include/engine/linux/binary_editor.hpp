#pragma once

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
        struct Binary<HostOS::kLinux> : LIEF::ELF::Binary {};

        template <>
        struct Section<HostOS::kLinux> : LIEF::ELF::Section {};

        extern "C" Address get_entry_point_ra() noexcept;

        /**
         * Concrete implementation of BinaryEditor specific for ELF binaries.
         */
        template <>
        class CustomBinaryEditor<HostOS::kLinux>
            : public CommonBinaryEditor<CustomBinaryEditor<HostOS::kLinux>> {
          public:
            static std::unique_ptr<
                BinaryEditor<CustomBinaryEditor<HostOS::kLinux>>>
            build(const std::string &path) noexcept;

            static std::unique_ptr<
                BinaryEditor<CustomBinaryEditor<HostOS::kLinux>>>
            build(const std::vector<std::uint8_t> &raw,
                  const std::string &name) noexcept;

            static inline std::unique_ptr<
                BinaryEditor<CustomBinaryEditor<HostOS::kLinux>>>
            build(std::istream &src, std::size_t size,
                  const std::string &name) noexcept {
                return CommonBinaryEditor<
                    CustomBinaryEditor<HostOS::kLinux>>::build(src, size, name);
            }

            inline Address first_execution_va() const noexcept {
                return this->bin_->entrypoint();
            }

            Address exec_first(Address va) noexcept;

            Error inject_section(const std::string &name,
                                 const RawCode &content) noexcept;

            Error update_content(const std::string &name,
                                 const RawCode &content) noexcept;

            static constexpr Address kPageSize = 4096;

          protected:
            CustomBinaryEditor(std::unique_ptr<LIEF::ELF::Binary> &&bin,
                               LIEF::ELF::Section &text_section) noexcept;

            inline bool
            has_section_impl(const std::string &name) const noexcept {
                return this->bin_->get_section(kSectionPrefix + name) !=
                       nullptr;
            }

            inline Section<HostOS::kLinux> *
            get_section_impl(const std::string &name) noexcept {
                return static_cast<Section<HostOS::kLinux> *>(
                    this->bin_->get_section(kSectionPrefix + name));
            }
            inline const Section<HostOS::kLinux> *
            get_section_impl(const std::string &name) const noexcept {
                return static_cast<Section<HostOS::kLinux> *>(
                    this->bin_->get_section(kSectionPrefix + name));
            }

            inline Section<HostOS::kLinux> &get_text_section_impl() noexcept {
                return static_cast<Section<HostOS::kLinux> &>(
                    this->text_section_);
            }
            inline const Section<HostOS::kLinux> &
            get_text_section_impl() const noexcept {
                return static_cast<Section<HostOS::kLinux> &>(
                    this->text_section_);
            }

            inline Binary<HostOS::kLinux> &get_bin_impl() noexcept {
                return static_cast<Binary<HostOS::kLinux> &>(*this->bin_);
            }
            inline const Binary<HostOS::kLinux> &get_bin_impl() const noexcept {
                return static_cast<Binary<HostOS::kLinux> &>(*this->bin_);
            }

            inline Address get_entry_point_ra_impl() const noexcept {
                return impl::get_entry_point_ra();
            }

          private:
            /**
             * Check if the binary passed is a valid one, and if it is create a
             * new CustomBinaryEditor<HostOS::kLinux>.
             */
            static std::unique_ptr<
                BinaryEditor<CustomBinaryEditor<HostOS::kLinux>>>
            check_and_init(std::unique_ptr<LIEF::ELF::Binary> &&bin);

            static const std::string kSectionPrefix;
            std::unique_ptr<LIEF::ELF::Binary> bin_;
            LIEF::ELF::Section &text_section_;
        };

    } // namespace impl

} // namespace poly