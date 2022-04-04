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

// Needed to avoid some clash between enums and symbols defined in Windows.h,
// which is used by some of the imports
#ifdef IMAGE_SCN_MEM_EXECUTE
#define POLY_IMAGE_SCN_MEM_EXECUTE IMAGE_SCN_MEM_EXECUTE
#undef IMAGE_SCN_MEM_EXECUTE
#endif
#ifdef IMAGE_SCN_MEM_READ
#define POLY_IMAGE_SCN_MEM_READ IMAGE_SCN_MEM_READ
#undef IMAGE_SCN_MEM_READ
#endif

namespace poly {

    namespace impl {

        template <>
        struct Binary<poly::HostOS::kWindows> : LIEF::PE::Binary {};

        template <>
        struct Section<poly::HostOS::kWindows> : LIEF::PE::Section {};

        extern "C" Address get_entry_point_ra();

    } // namespace impl

    template <>
    std::unique_ptr<impl::Binary<HostOS::kWindows>>
    CommonBinaryEditor<HostOS::kWindows>::parse_bin(const std::string name) {
        auto bin = LIEF::PE::Parser::parse(name);

        return std::move(
            impl::static_unique_ptr_cast<impl::Binary<HostOS::kWindows>>(
                std::move(bin)));
    }

    template <>
    impl::Section<HostOS::kWindows> *
    CommonBinaryEditor<HostOS::kWindows>::get_text_section() {
        auto *section = bin_->get_section(".text");

        return static_cast<impl::Section<HostOS::kWindows> *>(section);
    }

    template <>
    Address CommonBinaryEditor<HostOS::kWindows>::get_entry_point_va() {
        return bin_->offset_to_virtual_address(bin_->entrypoint()) -
               bin_->imagebase();
    }

    template <>
    impl::Section<HostOS::kWindows> *
    CommonBinaryEditor<HostOS::kWindows>::get_section(const std::string &name) {
        return static_cast<impl::Section<HostOS::kWindows> *>(
            bin_->get_section(name));
    }

    template <>
    CommonBinaryEditor<HostOS::kWindows>::CommonBinaryEditor(
        const std::string name)
        : bin_{parse_bin(name)}, text_section_{get_text_section()},
          entry_point_va_{get_entry_point_va()} {}

    template <>
    Address CommonBinaryEditor<HostOS::kWindows>::text_section_ra() {
        auto entry_address = impl::get_entry_point_ra();

        return entry_address - entry_point_va_;
    }

    template <>
    std::unique_ptr<impl::Section<HostOS::kWindows>>
    CommonBinaryEditor<HostOS::kWindows>::create_new_section(
        const std::string &name, const std::uint8_t *content,
        std::uint64_t size) {
        auto section = std::make_unique<LIEF::PE::Section>(name);

        // say that the new section is executable and readable
        section->add_characteristic(
            LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_EXECUTE);
        section->add_characteristic(
            LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_READ);

        section->content(std::vector<uint8_t>{content, content + size});

        return std::move(
            impl::static_unique_ptr_cast<impl::Section<HostOS::kWindows>>(
                std::move(section)));
    }

    template <>
    Error CommonBinaryEditor<HostOS::kWindows>::inject_section(
        const std::string &name, const ExecutableCode &content) {
        // TODO: implement it

        return Error::kNone;
    }

    template <>
    Error CommonBinaryEditor<HostOS::kWindows>::inject_section(
        const std::string &name, const std::vector<std::uint8_t> &content) {
        if (has_section(name)) {
            return Error::kSectionAlreadyExists;
        }

        bin_->add_section(
            *create_new_section(name, content.data(), content.size()),
            LIEF::PE::PE_SECTION_TYPES::TEXT);

        return Error::kNone;
    }

    template <>
    Address
    CommonBinaryEditor<HostOS::kWindows>::replace_entry(Address new_entry) {
        bin_->optional_header().addressof_entrypoint(new_entry);

        auto old_entry_point = entry_point_va_;
        entry_point_va_ = get_entry_point_va();

        return old_entry_point;
    }

    template <>
    Error CommonBinaryEditor<HostOS::kWindows>::update_content(
        const std::string &name, const std::vector<std::uint8_t> &content) {
        if (!has_section(name))
            return Error::kSectionNotFound;

        auto *section = get_section(name);

        // must be set also this, otherwise the new content will be truncated
        section->virtual_size(content.size());
        section->size(content.size());
        section->content(content);

        return Error::kNone;
    }

} // namespace poly

#ifdef POLY_IMAGE_SCN_MEM_EXECUTE
#define IMAGE_SCN_MEM_EXECUTE POLY_IMAGE_SCN_MEM_EXECUTE
#undef POLY_IMAGE_SCN_MEM_EXECUTE
#endif
#ifdef POLY_IMAGE_SCN_MEM_READ
#define IMAGE_SCN_MEM_READ POLY_IMAGE_SCN_MEM_READ
#undef POLY_IMAGE_SCN_MEM_READ
#endif