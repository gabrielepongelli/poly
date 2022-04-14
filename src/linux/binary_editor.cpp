#include "engine/binary_editor.hpp"

#include <cstdint>

#include <memory>
#include <string>
#include <vector>

#include <LIEF/LIEF.hpp>

#include "engine/enums.hpp"
#include "engine/host_properties.hpp"
#include "engine/utils.hpp"

namespace poly {

    template <>
    std::unique_ptr<impl::Binary<HostOS::kLinux>>
    CommonBinaryEditor<HostOS::kLinux>::parse_bin(
        const std::string name) noexcept {
        auto bin = LIEF::ELF::Parser::parse(name);

        return impl::static_unique_ptr_cast<impl::Binary<HostOS::kLinux>>(
            std::move(bin));
    }

    template <>
    impl::Section<HostOS::kLinux> *
    CommonBinaryEditor<HostOS::kLinux>::get_text_section(
        impl::Binary<HostOS::kLinux> &bin) noexcept {
        auto *section = bin.text_section();

        return static_cast<impl::Section<HostOS::kLinux> *>(section);
    }

    template <>
    Address CommonBinaryEditor<HostOS::kLinux>::get_entry_point_va(
        impl::Binary<HostOS::kLinux> &bin,
        impl::Section<HostOS::kLinux> &) noexcept {
        auto &text_segment =
            *bin.segment_from_virtual_address(bin.entrypoint());
        auto entry = bin.entrypoint() + text_segment.virtual_address();

        return entry;
    }

    template <>
    Address
    CommonBinaryEditor<HostOS::kLinux>::text_section_ra() const noexcept {
        auto entry_address = impl::get_entry_point_ra();

        entry_address -=
            bin_->entrypoint() -
            bin_->section_from_offset(bin_->entrypoint())->virtual_address();

        return entry_address;
    }

    template <>
    std::unique_ptr<impl::Section<HostOS::kLinux>>
    CommonBinaryEditor<HostOS::kLinux>::create_new_section(
        const std::string &name, const RawCode &content) noexcept {
        auto section = std::make_unique<LIEF::ELF::Section>(name);

        // say that the new section contains executable code
        *section += LIEF::ELF::ELF_SECTION_FLAGS::SHF_ALLOC;
        *section += LIEF::ELF::ELF_SECTION_FLAGS::SHF_EXECINSTR;

        section->content(std::vector<uint8_t>{content.begin(), content.end()});

        return impl::static_unique_ptr_cast<impl::Section<HostOS::kLinux>>(
            std::move(section));
    }

    template <>
    Error CommonBinaryEditor<HostOS::kLinux>::inject_section(
        const std::string &name, const RawCode &content) noexcept {
        if (has_section(name)) {
            return Error::kSectionAlreadyExists;
        }

        bin_->add(*create_new_section(name, content));

        return Error::kNone;
    }

    template <>
    Address CommonBinaryEditor<HostOS::kLinux>::replace_entry(
        Address new_entry) noexcept {
        bin_->header().entrypoint(new_entry);

        auto old_entry_point = entry_point_va_;
        entry_point_va_ = get_entry_point_va(*bin_, *text_section_);

        return old_entry_point;
    }

} // namespace poly