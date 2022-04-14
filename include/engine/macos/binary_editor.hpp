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
        struct Binary<poly::HostOS::kMacOS> : LIEF::MachO::Binary {};

        template <>
        struct Section<poly::HostOS::kMacOS> : LIEF::MachO::Section {};

        extern "C" Address get_entry_point_ra() noexcept;

    } // namespace impl

    template <>
    std::unique_ptr<impl::Binary<HostOS::kMacOS>>
    CommonBinaryEditor<HostOS::kMacOS>::parse_bin(
        const std::string name) noexcept;

    template <>
    impl::Section<HostOS::kMacOS> *
    CommonBinaryEditor<HostOS::kMacOS>::get_text_section(
        impl::Binary<HostOS::kMacOS> &bin) noexcept;

    template <>
    Address CommonBinaryEditor<HostOS::kMacOS>::get_entry_point_va(
        impl::Binary<HostOS::kMacOS> &bin,
        impl::Section<HostOS::kMacOS> &text_sect) noexcept;

    template <>
    Address
    CommonBinaryEditor<HostOS::kMacOS>::text_section_ra() const noexcept;

    template <>
    std::unique_ptr<impl::Section<HostOS::kMacOS>>
    CommonBinaryEditor<HostOS::kMacOS>::create_new_section(
        const std::string &name, const RawCode &content) noexcept;

    template <>
    Error CommonBinaryEditor<HostOS::kMacOS>::inject_section(
        const std::string &name, const RawCode &content) noexcept;

    template <>
    Address CommonBinaryEditor<HostOS::kMacOS>::replace_entry(
        Address new_entry) noexcept;

} // namespace poly