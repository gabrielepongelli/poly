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
        struct Binary<poly::HostOS::kLinux> : LIEF::ELF::Binary {};

        template <>
        struct Section<poly::HostOS::kLinux> : LIEF::ELF::Section {};

        extern "C" Address get_entry_point_ra() noexcept;

    } // namespace impl

    template <>
    std::unique_ptr<impl::Binary<HostOS::kLinux>>
    CommonBinaryEditor<HostOS::kLinux>::parse_bin(
        const std::string name) noexcept;

    template <>
    impl::Section<HostOS::kLinux> *
    CommonBinaryEditor<HostOS::kLinux>::get_text_section(
        impl::Binary<HostOS::kLinux> &bin) noexcept;

    template <>
    Address CommonBinaryEditor<HostOS::kLinux>::get_entry_point_va(
        impl::Binary<HostOS::kLinux> &bin,
        impl::Section<HostOS::kLinux> &) noexcept;

    template <>
    Address
    CommonBinaryEditor<HostOS::kLinux>::text_section_ra() const noexcept;

    template <>
    std::unique_ptr<impl::Section<HostOS::kLinux>>
    CommonBinaryEditor<HostOS::kLinux>::create_new_section(
        const std::string &name, const RawCode &content) noexcept;

    template <>
    Error CommonBinaryEditor<HostOS::kLinux>::inject_section(
        const std::string &name, const RawCode &content) noexcept;

    template <>
    Address CommonBinaryEditor<HostOS::kLinux>::replace_entry(
        Address new_entry) noexcept;

} // namespace poly