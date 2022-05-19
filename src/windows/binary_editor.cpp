#include "poly/windows/binary_editor.hpp"

#include <cstdint>

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include <LIEF/LIEF.hpp>

#include "poly/binary_editor.hpp"
#include "poly/enums.hpp"
#include "poly/filesystem.hpp"
#include "poly/host_properties.hpp"
#include "poly/utils.hpp"

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
#ifdef IMAGE_SCN_CNT_CODE
#define POLY_IMAGE_SCN_CNT_CODE IMAGE_SCN_CNT_CODE
#undef IMAGE_SCN_CNT_CODE
#endif
#ifdef IMAGE_FILE_EXECUTABLE_IMAGE
#define POLY_IMAGE_FILE_EXECUTABLE_IMAGE IMAGE_FILE_EXECUTABLE_IMAGE
#undef IMAGE_FILE_EXECUTABLE_IMAGE
#endif

namespace poly {

    namespace impl {

        const std::string
            CustomBinaryEditor<HostOS::kWindows>::kSectionPrefix_ = ".";

        std::unique_ptr<BinaryEditor<CustomBinaryEditor<HostOS::kWindows>>>
        CustomBinaryEditor<HostOS::kWindows>::build(
            const fs::path &path) noexcept {
            auto bin = LIEF::PE::Parser::parse(path.string());

            return check_and_init(std::move(bin));
        }

        std::unique_ptr<BinaryEditor<CustomBinaryEditor<HostOS::kWindows>>>
        CustomBinaryEditor<HostOS::kWindows>::build(
            const std::vector<std::uint8_t> &raw,
            const fs::path &path) noexcept {
            auto bin = LIEF::PE::Parser::parse(raw, path.string());

            return check_and_init(std::move(bin));
        }

        Address CustomBinaryEditor<HostOS::kWindows>::first_execution_va()
            const noexcept {
            if (this->has_tls()) {
                return this->first_tls_callback();
            } else {
                return this->bin_->entrypoint() - this->bin_->imagebase();
            }
        }

        Address
        CustomBinaryEditor<HostOS::kWindows>::exec_first(Address va) noexcept {
            auto old = this->first_execution_va();

            if (this->has_tls()) {
                this->first_tls_callback(va);
            } else {
                this->bin_->optional_header().addressof_entrypoint(va);
            }

            return old;
        }

        Error CustomBinaryEditor<HostOS::kWindows>::inject_section(
            const std::string &name, const RawCode &content) noexcept {
            if (this->has_section_impl(name)) {
                return Error::kSectionAlreadyExists;
            }

            // create the new section with the generated code inside
            LIEF::PE::Section section({content.begin(), content.end()},
                                      kSectionPrefix_ + name);

            // say that the new section is executable and readable
            section.add_characteristic(
                LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_EXECUTE);
            section.add_characteristic(
                LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_READ);
            section.add_characteristic(
                LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_CNT_CODE);

            this->bin_->add_section(section, LIEF::PE::PE_SECTION_TYPES::TEXT);

            return Error::kNone;
        }

        Error CustomBinaryEditor<HostOS::kWindows>::update_content(
            const std::string &name, const RawCode &content) noexcept {
            if (!ProtectedAccessor::has_section(*this->real(), name))
                return Error::kSectionNotFound;

            auto *section = ProtectedAccessor::get_section(*this->real(), name);

            // must be done, otherwise with g++ the size will not be really
            // updated
            section->virtual_size(content.size());

            section->size(content.size());
            section->content({content.begin(), content.end()});

            return Error::kNone;
        }

        Address CustomBinaryEditor<HostOS::kWindows>::get_imported_function_va(
            const std::string &import_name,
            const std::string &function_name) const noexcept {
            auto *import = this->bin_->get_import(import_name);

            if (import == nullptr ||
                import->get_entry(function_name) == nullptr) {
                return 0;
            }

            return import->get_function_rva_from_iat(function_name) +
                   import->import_address_table_rva();
        }

        void CustomBinaryEditor<HostOS::kWindows>::save_changes(
            const fs::path &path) noexcept {
            LIEF::PE::Builder builder(*bin_);

            builder.build();

            if (path.empty()) {
                builder.write(bin_->name());
            } else {
                builder.write(path.string());
            }
        }

        CustomBinaryEditor<HostOS::kWindows>::CustomBinaryEditor(
            std::unique_ptr<LIEF::PE::Binary> &&bin,
            LIEF::PE::Section &text_section) noexcept
            : bin_{std::move(bin)}, text_section_{text_section} {}

        std::unique_ptr<BinaryEditor<CustomBinaryEditor<HostOS::kWindows>>>
        CustomBinaryEditor<HostOS::kWindows>::check_and_init(
            std::unique_ptr<LIEF::PE::Binary> &&bin) {
            if (bin == nullptr || ((bin->header().characteristics() &
                                    LIEF::PE::HEADER_CHARACTERISTICS::
                                        IMAGE_FILE_EXECUTABLE_IMAGE) !=
                                   LIEF::PE::HEADER_CHARACTERISTICS::
                                       IMAGE_FILE_EXECUTABLE_IMAGE)) {
                return nullptr;
            }

            auto *text_sect = bin->get_section(kSectionPrefix_ + "text");

            if (text_sect == nullptr) {
                return nullptr;
            }

            std::unique_ptr<BinaryEditor<CustomBinaryEditor<HostOS::kWindows>>>
                editor(new CustomBinaryEditor<HostOS::kWindows>(std::move(bin),
                                                                *text_sect));

            return editor;
        }

        bool CustomBinaryEditor<HostOS::kWindows>::has_tls() const noexcept {
            if (!this->bin_->has_tls()) {
                return false;
            }

            return this->bin_->tls().callbacks().size() > 0;
        }

        Address CustomBinaryEditor<HostOS::kWindows>::first_tls_callback()
            const noexcept {
            if (!this->has_tls()) {
                return 0;
            }

            auto res =
                this->bin_->tls().callbacks().at(0) - this->bin_->imagebase();

            return res;
        }

        Error CustomBinaryEditor<HostOS::kWindows>::first_tls_callback(
            Address va) noexcept {
            if (!this->has_tls()) {
                return Error::kSectionNotFound;
            }

            auto &tls = this->bin_->tls();
            auto patch = va + this->bin_->imagebase();

            this->bin_->patch_address(tls.addressof_callbacks(), patch,
                                      kByteWordSize,
                                      LIEF::Binary::VA_TYPES::VA);

            return Error::kNone;
        }

    } // namespace impl

} // namespace poly

#ifdef POLY_IMAGE_SCN_MEM_EXECUTE
#define IMAGE_SCN_MEM_EXECUTE POLY_IMAGE_SCN_MEM_EXECUTE
#undef POLY_IMAGE_SCN_MEM_EXECUTE
#endif
#ifdef POLY_IMAGE_SCN_MEM_READ
#define IMAGE_SCN_MEM_READ POLY_IMAGE_SCN_MEM_READ
#undef POLY_IMAGE_SCN_MEM_READ
#endif
#ifdef POLY_IMAGE_SCN_CNT_CODE
#define IMAGE_SCN_CNT_CODE POLY_IMAGE_SCN_CNT_CODE
#undef POLY_IMAGE_SCN_CNT_CODE
#endif
#ifdef POLY_IMAGE_FILE_EXECUTABLE_IMAGE
#define IMAGE_FILE_EXECUTABLE_IMAGE POLY_IMAGE_FILE_EXECUTABLE_IMAGE
#undef POLY_IMAGE_FILE_EXECUTABLE_IMAGE
#endif