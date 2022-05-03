#pragma once

#include <cstdint>

#include <istream>
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

    namespace impl {

        template <class Real>
        std::unique_ptr<BinaryEditor<Real>>
        CommonBinaryEditor<Real>::build(std::istream &src, std::size_t size,
                                        const std::string &name) noexcept {
            std::vector<std::uint8_t> raw(size, 0);
            try {
                src.read(reinterpret_cast<char *>(raw.data()), size);
            } catch (std::ios_base::failure &e) {
                if ((src.exceptions() & std::ios_base::eofbit) !=
                    std::ios_base::eofbit) {
                    return nullptr;
                }
            }

            return std::move(Real::build(raw, name));
        }

        template <class Real>
        Address CommonBinaryEditor<Real>::align_to_page_size(
            Address addr, std::size_t &len) noexcept {
            Address end = len + addr;
            Address start = addr & ~(Real::kPageSize - 1);

            len = end - start;

            return start;
        }

        template <class Real>
        Address CommonBinaryEditor<Real>::text_section_ra() const noexcept {
            auto entry_address =
                ProtectedAccessor::get_entry_point_ra(*this->real());

            entry_address -=
                ProtectedAccessor::get_bin(*this->real()).entrypoint() -
                ProtectedAccessor::get_text_section(*this->real())
                    .virtual_address();

            return entry_address;
        };

        template <class Real>
        inline Address
        CommonBinaryEditor<Real>::text_section_va() const noexcept {
            return ProtectedAccessor::get_text_section(*this->real())
                .virtual_address();
        }

        template <class Real>
        inline std::uint64_t
        CommonBinaryEditor<Real>::text_section_size() const noexcept {
            return ProtectedAccessor::get_text_section(*this->real()).size();
        }

        template <class Real>
        inline RawCode
        CommonBinaryEditor<Real>::text_section_content() const noexcept {
            auto content =
                ProtectedAccessor::get_text_section(*this->real()).content();
            return {(std::uint8_t *)content.data(), content.size()};
        }

        template <class Real>
        inline Error CommonBinaryEditor<Real>::update_text_section_content(
            const RawCode &content) noexcept {
            return this->real()->update_content(
                ProtectedAccessor::get_text_section(*this->real()).name(),
                content);
        }

        template <class Real>
        Error CommonBinaryEditor<Real>::calculate_va(
            const std::string &name, Address &va,
            std::uint64_t offset) const noexcept {
            if (!ProtectedAccessor::has_section(*this->real(), name))
                return Error::kSectionNotFound;

            auto *section = ProtectedAccessor::get_section(*this->real(), name);

            if (section->size() < offset)
                return Error::kInvalidOffset;

            va = section->virtual_address() + offset;

            return Error::kNone;
        }

        template <class Real>
        Error CommonBinaryEditor<Real>::update_content(
            const std::string &name, const RawCode &content) noexcept {
            if (!ProtectedAccessor::has_section(*this->real(), name))
                return Error::kSectionNotFound;

            auto *section = ProtectedAccessor::get_section(*this->real(), name);

            section->size(content.size());
            section->content({content.begin(), content.end()});

            return Error::kNone;
        }

        template <class Real>
        RawCode CommonBinaryEditor<Real>::get_section_content(
            const std::string &name) const noexcept {
            if (!ProtectedAccessor::has_section(*this->real(), name)) {
                return {};
            }

            auto res =
                ProtectedAccessor::get_section(*this->real(), name)->content();

            return {(std::uint8_t *)res.data(), res.size()};
        }

        template <class Real>
        void CommonBinaryEditor<Real>::save_changes(
            const std::string &path) noexcept {
            if (path.empty()) {
                ProtectedAccessor::get_bin(*this->real())
                    .write(ProtectedAccessor::get_bin(*this->real()).name());
            } else {
                ProtectedAccessor::get_bin(*this->real()).write(path);
            }
        }

        template <class Real>
        inline bool CommonBinaryEditor<Real>::ProtectedAccessor::has_section(
            const Real &real, const std::string &name) noexcept {
            constexpr bool (Real::*fn)(const std::string &) const noexcept =
                &ProtectedAccessor::has_section_impl;

            return (real.*fn)(std::forward<const std::string &>(name));
        }

        template <class Real>
        inline OsSection *
        CommonBinaryEditor<Real>::ProtectedAccessor::get_section(
            Real &real, const std::string &name) noexcept {
            constexpr OsSection *(Real::*fn)(const std::string &) noexcept =
                &ProtectedAccessor::get_section_impl;

            return (real.*fn)(std::forward<const std::string &>(name));
        }

        template <class Real>
        inline const OsSection *
        CommonBinaryEditor<Real>::ProtectedAccessor::get_section(
            const Real &real, const std::string &name) noexcept {
            constexpr const OsSection *(Real::*fn)(const std::string &)
                const noexcept = &ProtectedAccessor::get_section_impl;

            return (real.*fn)(std::forward<const std::string &>(name));
        }

        template <class Real>
        inline OsSection &
        CommonBinaryEditor<Real>::ProtectedAccessor::get_text_section(
            Real &real) noexcept {
            constexpr OsSection &(Real::*fn)() noexcept =
                &ProtectedAccessor::get_text_section_impl;

            return (real.*fn)();
        }

        template <class Real>
        inline const OsSection &
        CommonBinaryEditor<Real>::ProtectedAccessor::get_text_section(
            const Real &real) noexcept {
            constexpr const OsSection &(Real::*fn)() const noexcept =
                &ProtectedAccessor::get_text_section_impl;

            return (real.*fn)();
        }

        template <class Real>
        inline OsBinary &CommonBinaryEditor<Real>::ProtectedAccessor::get_bin(
            Real &real) noexcept {
            constexpr OsBinary &(Real::*fn)() noexcept =
                &ProtectedAccessor::get_bin_impl;

            return (real.*fn)();
        }

        template <class Real>
        inline const OsBinary &
        CommonBinaryEditor<Real>::ProtectedAccessor::get_bin(
            const Real &real) noexcept {
            constexpr const OsBinary &(Real::*fn)() const noexcept =
                &ProtectedAccessor::get_bin_impl;

            return (real.*fn)();
        }

        template <class Real>
        inline Address
        CommonBinaryEditor<Real>::ProtectedAccessor::get_entry_point_ra(
            const Real &real) noexcept {
            constexpr Address (Real::*fn)() const noexcept =
                &ProtectedAccessor::get_entry_point_ra_impl;

            return (real.*fn)();
        }

    } // namespace impl

} // namespace poly