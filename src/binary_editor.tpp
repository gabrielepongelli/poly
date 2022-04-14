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

#if defined(POLY_LINUX)
#include "engine/linux/binary_editor.hpp"
#elif defined(POLY_MACOS)
#include "engine/macos/binary_editor.hpp"
#elif defined(POLY_WINDOWS)
#include "engine/windows/binary_editor.hpp"
#endif

namespace poly {

    template <HostOS OS>
    inline std::unique_ptr<impl::Binary<OS>>
    CommonBinaryEditor<OS>::parse_bin(const std::string name) noexcept {
        return nullptr;
    };

    template <HostOS OS>
    inline impl::Section<OS> *
    CommonBinaryEditor<OS>::get_text_section(impl::Binary<OS> &bin) noexcept {
        return nullptr;
    };

    template <HostOS OS>
    inline Address CommonBinaryEditor<OS>::get_entry_point_va(
        impl::Binary<OS> &bin, impl::Section<OS> &text_sect) noexcept {
        return 0;
    };

    template <HostOS OS>
    std::unique_ptr<BinaryEditorInterface<CommonBinaryEditor<OS>>>
    CommonBinaryEditor<OS>::build(const std::string &path) noexcept {
        auto bin = parse_bin(path);

        if (bin == nullptr) {
            return nullptr;
        }

        auto *text_sect = get_text_section(*bin);

        if (text_sect == nullptr) {
            return nullptr;
        }

        auto entry_va = get_entry_point_va(*bin, *text_sect);

        if (entry_va == 0) {
            return nullptr;
        }

        std::unique_ptr<BinaryEditorInterface<CommonBinaryEditor<OS>>> editor(
            new CommonBinaryEditor<OS>(std::move(bin), text_sect, entry_va));

        return editor;
    }

    template <HostOS OS>
    CommonBinaryEditor<OS>::CommonBinaryEditor(
        std::unique_ptr<impl::Binary<OS>> &&bin,
        impl::Section<OS> *text_section, Address entry_va) noexcept
        : bin_{std::move(bin)}, text_section_{text_section}, entry_point_va_{
                                                                 entry_va} {}

    template <HostOS OS>
    inline Address CommonBinaryEditor<OS>::entry_point() const noexcept {
        return entry_point_va_;
    }

    template <HostOS OS>
    inline Address CommonBinaryEditor<OS>::text_section_ra() const noexcept {
        return 0;
    };

    template <HostOS OS>
    inline Address CommonBinaryEditor<OS>::text_section_va() const noexcept {
        return text_section_->virtual_address();
    }

    template <HostOS OS>
    inline std::uint64_t
    CommonBinaryEditor<OS>::text_section_size() const noexcept {
        return text_section_->size();
    }

    template <HostOS OS>
    inline Error
    CommonBinaryEditor<OS>::inject_section(const std::string &name,
                                           const RawCode &content) noexcept {
        return Error::kNone;
    };

    template <HostOS OS>
    inline Address
    CommonBinaryEditor<OS>::replace_entry(Address new_entry) noexcept {
        return 0;
    };

    template <HostOS OS>
    inline bool CommonBinaryEditor<OS>::has_section(
        const std::string &name) const noexcept {
        return bin_->get_section(name) != nullptr;
    }

    template <HostOS OS>
    inline impl::Section<OS> *CommonBinaryEditor<OS>::get_section(
        const std::string &name) const noexcept {
        return static_cast<impl::Section<OS> *>(bin_->get_section(name));
    }

    template <HostOS OS>
    Error
    CommonBinaryEditor<OS>::calculate_va(const std::string &name, Address &va,
                                         std::uint64_t offset) const noexcept {
        if (!has_section(name))
            return Error::kSectionNotFound;

        auto *section = get_section(name);

        if (section->size() < offset)
            return Error::kInvalidOffset;

        offset += section->offset();
        va = bin_->offset_to_virtual_address(offset);

        return Error::kNone;
    }

    template <HostOS OS>
    Error
    CommonBinaryEditor<OS>::update_content(const std::string &name,
                                           const RawCode &content) noexcept {
        if (!has_section(name))
            return Error::kSectionNotFound;

        auto *section = get_section(name);

        section->size(content.size());
        section->content({content.begin(), content.end()});

        return Error::kNone;
    }

    template <HostOS OS>
    inline std::unique_ptr<impl::Section<OS>>
    CommonBinaryEditor<OS>::create_new_section(
        const std::string &name, const RawCode &content) noexcept {
        return nullptr;
    };

    template <HostOS OS>
    inline void CommonBinaryEditor<OS>::save_changes() noexcept {
        bin_->write(bin_->name());
    }

} // namespace poly