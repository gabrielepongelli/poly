#pragma once

#include <LIEF/LIEF.hpp>

#include "engine/binary_editor.hpp"

namespace poly {

    namespace impl {

        template <>
        struct Binary<poly::HostOS::kLinux> : LIEF::ELF::Binary {};

        template <>
        struct Section<poly::HostOS::kLinux> : LIEF::ELF::Section {};

        extern "C" Address get_entry_point_ra() noexcept;

    } // namespace impl

} // namespace poly