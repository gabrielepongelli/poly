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
    std::unique_ptr<impl::Binary<HostOS::kMacOS>>
    CommonBinaryEditor<HostOS::kMacOS>::parse_bin(
        const std::string name) noexcept {
        auto bin = LIEF::MachO::Parser::parse(name)->take(
            LIEF::MachO::CPU_TYPES::CPU_TYPE_X86_64);

        return impl::static_unique_ptr_cast<impl::Binary<HostOS::kMacOS>>(
            std::move(bin));
    }

    template <>
    impl::Section<HostOS::kMacOS> *
    CommonBinaryEditor<HostOS::kMacOS>::get_text_section(
        impl::Binary<HostOS::kMacOS> &bin) noexcept {
        auto *section = bin.get_section("__text");

        return static_cast<impl::Section<HostOS::kMacOS> *>(section);
    }

    template <>
    Address CommonBinaryEditor<HostOS::kMacOS>::get_entry_point_va(
        impl::Binary<HostOS::kMacOS> &bin,
        impl::Section<HostOS::kMacOS> &text_sect) noexcept {
        auto &segment_cmd = *text_sect.segment();
        auto entry_offset = bin.main_command()->entrypoint();

        return entry_offset + segment_cmd.virtual_address();
    }

    template <>
    Address
    CommonBinaryEditor<HostOS::kMacOS>::text_section_ra() const noexcept {
        auto entry_address = impl::get_entry_point_ra();

        // calculate the pointer which point to the start of the text section
        auto offset = bin_->main_command()->command_offset();
        entry_address -= offset;

        return entry_address;
    }

    template <>
    std::unique_ptr<impl::Section<HostOS::kMacOS>>
    CommonBinaryEditor<HostOS::kMacOS>::create_new_section(
        const std::string &name, const RawCode &content) noexcept {
        // create the new section with the generated code inside
        auto section = std::make_unique<LIEF::MachO::Section>(
            name,
            LIEF::MachO::Section::content_t{content.begin(), content.end()});

        // say that the new section contains executable code
        *section += LIEF::MachO::MACHO_SECTION_FLAGS::S_ATTR_SOME_INSTRUCTIONS;
        *section += LIEF::MachO::MACHO_SECTION_FLAGS::S_ATTR_PURE_INSTRUCTIONS;

        return impl::static_unique_ptr_cast<impl::Section<HostOS::kMacOS>>(
            std::move(section));
    }

    template <>
    Error CommonBinaryEditor<HostOS::kMacOS>::inject_section(
        const std::string &name, const RawCode &content) noexcept {
        if (has_section(name)) {
            return Error::kSectionAlreadyExists;
        }

        bin_->add_section(*create_new_section(name, content));

        return Error::kNone;
    }

    template <>
    Address CommonBinaryEditor<HostOS::kMacOS>::replace_entry(
        Address new_entry) noexcept {
        auto &segment_cmd = *text_section_->segment();

        bin_->main_command()->entrypoint(new_entry -
                                         segment_cmd.virtual_address());

        auto old_entry_point = entry_point_va_;
        entry_point_va_ = get_entry_point_va(*bin_, *text_section_);

        return old_entry_point;
    }

} // namespace poly