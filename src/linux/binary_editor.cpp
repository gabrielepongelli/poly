#include "poly/linux/binary_editor.hpp"

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

namespace poly {

    namespace impl {

        const std::string CustomBinaryEditor<HostOS::kLinux>::kSectionPrefix_ =
            ".";

        std::unique_ptr<BinaryEditor<CustomBinaryEditor<HostOS::kLinux>>>
        CustomBinaryEditor<HostOS::kLinux>::build(
            const fs::path &path) noexcept {
            auto bin = LIEF::ELF::Parser::parse(path.string());

            return check_and_init(std::move(bin));
        }

        std::unique_ptr<BinaryEditor<CustomBinaryEditor<HostOS::kLinux>>>
        CustomBinaryEditor<HostOS::kLinux>::build(
            const std::vector<std::uint8_t> &raw,
            const fs::path &path) noexcept {
            auto bin = LIEF::ELF::Parser::parse(raw, path.string());

            return check_and_init(std::move(bin));
        }

        Address
        CustomBinaryEditor<HostOS::kLinux>::exec_first(Address va) noexcept {
            auto old = this->first_execution_va();

            this->bin_->header().entrypoint(va);

            return old;
        }

        Error CustomBinaryEditor<HostOS::kLinux>::inject_section(
            const std::string &name, const RawCode &content) noexcept {
            if (this->has_section_impl(name)) {
                return Error::kSectionAlreadyExists;
            }

            LIEF::ELF::Section section(kSectionPrefix_ + name);

            // say that the new section contains executable code
            section += LIEF::ELF::ELF_SECTION_FLAGS::SHF_ALLOC;
            section += LIEF::ELF::ELF_SECTION_FLAGS::SHF_EXECINSTR;

            if (content.size() > 0) {
                section.content({content.begin(), content.end()});
            } else {
                // put at least 1 byte in the section content otherwise the
                // method Binary::segment_from_virtual_address would not work
                section.content({0});
            }

            this->bin_->add(section, true);

            return Error::kNone;
        }

        Error CustomBinaryEditor<HostOS::kLinux>::update_content(
            const std::string &name, const RawCode &content) noexcept {
            if (!this->has_section_impl(name)) {
                return Error::kSectionNotFound;
            }

            LIEF::ELF::Section *section = this->get_section_impl(name);
            int size_offset = content.size() - section->size();

            if (size_offset > 0) {
                this->bin_->extend(*section, size_offset);
            } else {
                section->size(content.size());
            }

            section->content({content.begin(), content.end()});

            return Error::kNone;
        }

        bool CustomBinaryEditor<HostOS::kLinux>::save_changes(
            const fs::path &path) noexcept {
            if (path.empty()) {
                this->bin_->write(this->bin_->name());
            } else {
                this->bin_->write(path.string());
            }

            return true;
        }

        CustomBinaryEditor<HostOS::kLinux>::CustomBinaryEditor(
            std::unique_ptr<LIEF::ELF::Binary> &&bin,
            LIEF::ELF::Section &text_section) noexcept
            : bin_{std::move(bin)}, text_section_{text_section} {}

        std::unique_ptr<BinaryEditor<CustomBinaryEditor<HostOS::kLinux>>>
        CustomBinaryEditor<HostOS::kLinux>::check_and_init(
            std::unique_ptr<LIEF::ELF::Binary> &&bin) {
            if (bin == nullptr) {
                return nullptr;
            }

            auto type = bin->header().abstract_object_type();
            if (type != LIEF::OBJECT_TYPES::TYPE_EXECUTABLE &&
                (type != LIEF::OBJECT_TYPES::TYPE_LIBRARY ||
                 bin->entrypoint() == 0)) {
                return nullptr;
            }

            auto *text_sect = bin->text_section();

            if (text_sect == nullptr) {
                return nullptr;
            }

            std::unique_ptr<BinaryEditor<CustomBinaryEditor<HostOS::kLinux>>>
                editor(new CustomBinaryEditor<HostOS::kLinux>(std::move(bin),
                                                              *text_sect));

            return editor;
        }

    } // namespace impl

} // namespace poly