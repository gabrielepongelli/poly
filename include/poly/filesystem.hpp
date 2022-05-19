#pragma once

#include "host_properties.hpp"

#ifdef POLY_WINDOWS
#ifndef SUBLANG_DEFAULT
#define SUBLANG_DEFAULT 0x01
#endif
#ifndef LANG_NEUTRAL
#define LANG_NEUTRAL 0x00
#endif
#endif

#include <ghc/filesystem.hpp>

namespace poly {

    namespace fs = ghc::filesystem;

} // namespace poly