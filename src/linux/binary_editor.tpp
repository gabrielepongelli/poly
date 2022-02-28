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
        struct Binary<poly::HostOS::kLinux> : LIEF::ELF::Binary {};

        template <>
        struct Section<poly::HostOS::kLinux> : LIEF::ELF::Section {};

        extern "C" Address get_entry_point_ra();

    } // namespace impl

    template <>
    std::unique_ptr<impl::Binary<HostOS::kLinux>>
    CommonBinaryEditor<HostOS::kLinux>::parse_bin(const std::string name) {
        auto bin = LIEF::ELF::Parser::parse(name);

        return std::move(
            impl::static_unique_ptr_cast<impl::Binary<HostOS::kLinux>>(
                std::move(bin)));
    }

    template <>
    impl::Section<HostOS::kLinux> *
    CommonBinaryEditor<HostOS::kLinux>::get_text_section() {
        auto *section = bin_->text_section();

        return static_cast<impl::Section<HostOS::kLinux> *>(section);
    }

    template <>
    Address CommonBinaryEditor<HostOS::kLinux>::get_entry_point_va() {
        auto &text_segment =
            bin_->segment_from_virtual_address(bin_->entrypoint());
        auto entry = bin_->entrypoint() + text_segment.virtual_address();

        return entry;
    }

    template <>
    bool
    CommonBinaryEditor<HostOS::kLinux>::has_section(const std::string &name) {
        return bin_->has_section(name);
    }

    template <>
    impl::Section<HostOS::kLinux> *
    CommonBinaryEditor<HostOS::kLinux>::get_section(const std::string &name) {
        return static_cast<impl::Section<HostOS::kLinux> *>(
            &bin_->get_section(name));
    }

    template <>
    CommonBinaryEditor<HostOS::kLinux>::CommonBinaryEditor(
        const std::string name)
        : bin_{parse_bin(name)}, text_section_{get_text_section()},
          entry_point_va_{get_entry_point_va()} {}

    template <>
    Address CommonBinaryEditor<HostOS::kLinux>::text_section_ra() const {
        auto entry_address = impl::get_entry_point_ra();

        entry_address -= bin_->entrypoint() - text_section_->virtual_address();

        return entry_address;
    }

    template <>
    std::unique_ptr<impl::Section<HostOS::kLinux>>
    CommonBinaryEditor<HostOS::kLinux>::create_new_section(
        const std::string &name, const std::uint8_t *content,
        std::uint64_t size) {
        auto section = std::make_unique<LIEF::ELF::Section>(name);

        // say that the new section contains executable code
        *section += LIEF::ELF::ELF_SECTION_FLAGS::SHF_ALLOC;
        *section += LIEF::ELF::ELF_SECTION_FLAGS::SHF_EXECINSTR;

        section->content(std::vector<uint8_t>{content, content + size});

        return std::move(
            impl::static_unique_ptr_cast<impl::Section<HostOS::kLinux>>(
                std::move(section)));
    }

    template <>
    BinaryEditorError CommonBinaryEditor<HostOS::kLinux>::inject_section(
        const std::string &name, const ExecutableCode &content) {
        // TODO: implement it

        return BinaryEditorError::kNone;
    }

    template <>
    BinaryEditorError CommonBinaryEditor<HostOS::kLinux>::inject_section(
        const std::string &name, const std::vector<std::uint8_t> &content) {
        if (has_section(name)) {
            return BinaryEditorError::kSectionAlreadyExists;
        }

        bin_->add_section(
            *create_new_section(name, content.data(), content.size()));

        return BinaryEditorError::kNone;
    }

    template <>
    Address
    CommonBinaryEditor<HostOS::kLinux>::replace_entry(Address new_entry) {
        bin_->header().entrypoint(new_entry);

        auto old_entry_point = entry_point_va_;
        entry_point_va_ = get_entry_point_va();

        return old_entry_point;
    }

} // namespace poly