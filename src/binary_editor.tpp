#pragma once

#include <cstdint>

#include <memory>
#include <string>
#include <vector>

#include <LIEF/LIEF.hpp>

#include "engine/binary_editor.hpp"
#include "engine/code_container.hpp"
#include "engine/enums.hpp"
#include "engine/host_properties.hpp"
#include "engine/utils.hpp"

namespace poly {

    template <HostOS OS>
    CommonBinaryEditor<OS>::CommonBinaryEditor(const std::string name){};

    template <HostOS OS>
    std::unique_ptr<impl::Binary<OS>>
    CommonBinaryEditor<OS>::parse_bin(const std::string name){};

    template <HostOS OS>
    impl::Section<OS> *CommonBinaryEditor<OS>::get_text_section(){};

    template <HostOS OS>
    Address CommonBinaryEditor<OS>::get_entry_point_va(){};

    template <HostOS OS>
    Address CommonBinaryEditor<OS>::entry_point() {
        return entry_point_va_;
    }

    template <HostOS OS>
    Address CommonBinaryEditor<OS>::text_section_ra(){};

    template <HostOS OS>
    Address CommonBinaryEditor<OS>::text_section_va() {
        return text_section_->virtual_address();
    }

    template <HostOS OS>
    std::uint64_t CommonBinaryEditor<OS>::text_section_size() {
        return text_section_->size();
    }

    template <HostOS OS>
    BinaryEditorError
    CommonBinaryEditor<OS>::inject_section(const std::string &name,
                                           const ExecutableCode &content){};

    template <HostOS OS>
    BinaryEditorError CommonBinaryEditor<OS>::inject_section(
        const std::string &name, const std::vector<std::uint8_t> &content){};

    template <HostOS OS>
    Address CommonBinaryEditor<OS>::replace_entry(Address new_entry){};

    template <HostOS OS>
    bool CommonBinaryEditor<OS>::has_section(const std::string &name) {}

    template <HostOS OS>
    impl::Section<OS> *
    CommonBinaryEditor<OS>::get_section(const std::string &name) {}

    template <HostOS OS>
    BinaryEditorError
    CommonBinaryEditor<OS>::calculate_va(const std::string &name, Address &va,
                                         std::uint64_t offset) {
        if (!has_section(name))
            return BinaryEditorError::kSectionNotFound;

        auto *section = get_section(name);

        if (section->size() < offset)
            return BinaryEditorError::kInvalidOffset;

        offset += section->offset();
        va = bin_->offset_to_virtual_address(offset);

        return BinaryEditorError::kNone;
    }

    template <HostOS OS>
    BinaryEditorError CommonBinaryEditor<OS>::update_content(
        const std::string &name, const std::vector<std::uint8_t> &content) {
        if (!has_section(name))
            return BinaryEditorError::kSectionNotFound;

        auto *section = get_section(name);

        section->size(content.size());
        section->content(content);

        return BinaryEditorError::kNone;
    }

    template <HostOS OS>
    BinaryEditorError
    CommonBinaryEditor<OS>::update_content(const std::string &name,
                                           const ExecutableCode &content) {
        // TODO: implement it

        return BinaryEditorError::kNone;
    }

    template <HostOS OS>
    std::unique_ptr<impl::Section<OS>>
    CommonBinaryEditor<OS>::create_new_section(const std::string &name,
                                               const std::uint8_t *content,
                                               std::uint64_t size){};

    template <HostOS OS>
    void CommonBinaryEditor<OS>::save_changes() {
        bin_->write(bin_->name());
    }

} // namespace poly

#if defined(POLY_LINUX)
#include "linux/binary_editor.tpp"
#elif defined(POLY_MACOS)
#include "macos/binary_editor.tpp"
#elif defined(POLY_WINDOWS)
#include "windows/binary_editor.tpp"
#endif