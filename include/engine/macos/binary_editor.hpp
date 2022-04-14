#pragma once

#include <LIEF/LIEF.hpp>

#include "engine/binary_editor.hpp"

namespace poly {

    namespace impl {

        template <>
        struct Binary<poly::HostOS::kMacOS> : LIEF::MachO::Binary {};

        template <>
        struct Section<poly::HostOS::kMacOS> : LIEF::MachO::Section {};

        extern "C" Address get_entry_point_ra() noexcept;

    } // namespace impl

} // namespace poly