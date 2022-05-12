#pragma once

#include <memory>
#include <string>
#include <vector>

#include <LIEF/LIEF.hpp>

#include "poly/binary_editor.hpp"
#include "poly/enums.hpp"
#include "poly/host_properties.hpp"
#include "poly/utils.hpp"

namespace poly {

    namespace impl {

        template <>
        struct Binary<HostOS::kWindows> : LIEF::PE::Binary {};

        template <>
        struct Section<HostOS::kWindows> : LIEF::PE::Section {};

        extern "C" Address get_entry_point_ra() noexcept;

        /**
         * Concrete implementation of BinaryEditor specific for PE binaries.
         */
        template <>
        class CustomBinaryEditor<HostOS::kWindows>
            : public CommonBinaryEditor<CustomBinaryEditor<HostOS::kWindows>> {
          public:
            static std::unique_ptr<
                BinaryEditor<CustomBinaryEditor<HostOS::kWindows>>>
            build(const std::string &path) noexcept;

            static std::unique_ptr<
                BinaryEditor<CustomBinaryEditor<HostOS::kWindows>>>
            build(const std::vector<std::uint8_t> &raw,
                  const std::string &name) noexcept;

            static inline std::unique_ptr<
                BinaryEditor<CustomBinaryEditor<HostOS::kWindows>>>
            build(std::istream &src, std::size_t size,
                  const std::string &name) noexcept {
                return CommonBinaryEditor<
                    CustomBinaryEditor<HostOS::kWindows>>::build(src, size,
                                                                 name);
            }

            /**
             * Retrieve the virtual address of the specified imported function.
             * @param import_name name of the import library where to search for
             * the imported function.
             * @param function_name name of the imported function to search for
             * inside the specified imported library.
             * @return a valid virtual address if the imported function (and the
             * import) is present, 0 otherwise.
             */
            Address get_imported_function_va(
                const std::string &import_name,
                const std::string &function_name) const noexcept;

            Address first_execution_va() const noexcept;

            Address exec_first(Address va) noexcept;

            inline Address text_section_ra() const noexcept {
                return CommonBinaryEditor<CustomBinaryEditor<
                           HostOS::kWindows>>::text_section_ra() +
                       this->bin_->imagebase();
            }

            Error inject_section(const std::string &name,
                                 const RawCode &content) noexcept;

            Error update_content(const std::string &name,
                                 const RawCode &content) noexcept;

            void save_changes(const std::string &path) noexcept;

          protected:
            CustomBinaryEditor(std::unique_ptr<LIEF::PE::Binary> &&bin,
                               LIEF::PE::Section &text_section) noexcept;

            inline bool
            has_section_impl(const std::string &name) const noexcept {
                return this->bin_->get_section(kSectionPrefix_ + name) !=
                       nullptr;
            }

            inline Section<HostOS::kWindows> *
            get_section_impl(const std::string &name) noexcept {
                return static_cast<Section<HostOS::kWindows> *>(
                    this->bin_->get_section(kSectionPrefix_ + name));
            }
            inline const Section<HostOS::kWindows> *
            get_section_impl(const std::string &name) const noexcept {
                return static_cast<Section<HostOS::kWindows> *>(
                    this->bin_->get_section(kSectionPrefix_ + name));
            }

            inline Section<HostOS::kWindows> &get_text_section_impl() noexcept {
                return static_cast<Section<HostOS::kWindows> &>(
                    this->text_section_);
            }
            inline const Section<HostOS::kWindows> &
            get_text_section_impl() const noexcept {
                return static_cast<Section<HostOS::kWindows> &>(
                    this->text_section_);
            }

            inline Binary<HostOS::kWindows> &get_bin_impl() noexcept {
                return static_cast<Binary<HostOS::kWindows> &>(*this->bin_);
            }
            inline const Binary<HostOS::kWindows> &
            get_bin_impl() const noexcept {
                return static_cast<Binary<HostOS::kWindows> &>(*this->bin_);
            }

            inline Address get_entry_point_ra_impl() const noexcept {
                return impl::get_entry_point_ra();
            }

            static constexpr Address kPageSize_ = 4096;
            static const std::string kSectionPrefix_;

          private:
            /**
             * Check if the binary passed is a valid one, and if it is create a
             * new CustomBinaryEditor<HostOS::kWindows>.
             */
            static std::unique_ptr<
                BinaryEditor<CustomBinaryEditor<HostOS::kWindows>>>
            check_and_init(std::unique_ptr<LIEF::PE::Binary> &&bin);

            /**
             * Check whether the binary has section for Thread Local Storage
             * with at least one callback address.
             */
            bool has_tls() const noexcept;

            /**
             * Retrieve the virtual address of the first tls callback executed
             * by the binary. If it hasn't any callback, the returned value is
             * 0.
             */
            Address first_tls_callback() const noexcept;

            /**
             * Overwrite the virtual address of the first tls callback of the
             * binary with the one specified.
             * @param va new virtual address.
             * @return kNone if no error is raised.
             */
            Error first_tls_callback(Address va) noexcept;

            std::unique_ptr<LIEF::PE::Binary> bin_;
            LIEF::PE::Section &text_section_;
        };

    } // namespace impl

} // namespace poly