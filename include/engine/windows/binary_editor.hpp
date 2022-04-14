#pragma once

#include <memory>
#include <string>

#include <LIEF/LIEF.hpp>

#include "engine/binary_editor.hpp"
#include "engine/enums.hpp"
#include "engine/utils.hpp"

namespace poly {

    namespace impl {

        template <>
        struct Binary<poly::HostOS::kWindows> : LIEF::PE::Binary {};

        template <>
        struct Section<poly::HostOS::kWindows> : LIEF::PE::Section {};

        extern "C" Address get_entry_point_ra() noexcept;

    } // namespace impl

    template <>
    std::unique_ptr<impl::Binary<HostOS::kWindows>>
    CommonBinaryEditor<HostOS::kWindows>::parse_bin(
        const std::string name) noexcept;

    template <>
    impl::Section<HostOS::kWindows> *
    CommonBinaryEditor<HostOS::kWindows>::get_text_section(
        impl::Binary<HostOS::kWindows> &bin) noexcept;

    template <>
    Address CommonBinaryEditor<HostOS::kWindows>::get_entry_point_va(
        impl::Binary<HostOS::kWindows> &bin,
        impl::Section<HostOS::kWindows> &) noexcept;

    template <>
    Address
    CommonBinaryEditor<HostOS::kWindows>::text_section_ra() const noexcept;

    template <>
    std::unique_ptr<impl::Section<HostOS::kWindows>>
    CommonBinaryEditor<HostOS::kWindows>::create_new_section(
        const std::string &name, const RawCode &content) noexcept;

    template <>
    Error CommonBinaryEditor<HostOS::kWindows>::inject_section(
        const std::string &name, const RawCode &content) noexcept;

    template <>
    Address CommonBinaryEditor<HostOS::kWindows>::replace_entry(
        Address new_entry) noexcept;

    template <>
    Error CommonBinaryEditor<HostOS::kWindows>::update_content(
        const std::string &name, const RawCode &content) noexcept;

} // namespace poly