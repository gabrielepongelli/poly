#include "engine/macos/binary_editor.hpp"

#include <cstdint>

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include <LIEF/LIEF.hpp>

#include "engine/binary_editor.hpp"
#include "engine/enums.hpp"
#include "engine/host_properties.hpp"
#include "engine/utils.hpp"

namespace poly {

    namespace impl {

        const std::string CustomBinaryEditor<HostOS::kMacOS>::kSectionPrefix =
            "__";

        std::unique_ptr<BinaryEditor<CustomBinaryEditor<HostOS::kMacOS>>>
        CustomBinaryEditor<HostOS::kMacOS>::build(
            const std::string &path) noexcept {
            auto fat_bin = LIEF::MachO::Parser::parse(path);

            if (fat_bin == nullptr) {
                return nullptr;
            }

            return check_and_init(
                fat_bin->take(LIEF::MachO::CPU_TYPES::CPU_TYPE_X86_64));
        }

        std::unique_ptr<BinaryEditor<CustomBinaryEditor<HostOS::kMacOS>>>
        CustomBinaryEditor<HostOS::kMacOS>::build(
            const std::vector<std::uint8_t> &raw,
            const std::string &name) noexcept {
            auto bin = LIEF::MachO::Parser::parse(raw, name)->take(
                LIEF::MachO::CPU_TYPES::CPU_TYPE_X86_64);

            return check_and_init(std::move(bin));
        }

        Address CustomBinaryEditor<HostOS::kMacOS>::first_execution_va()
            const noexcept {
            if (this->has_global_init()) {
                return this->first_global_init();
            } else {
                return this->bin_->entrypoint();
            }
        }

        Address
        CustomBinaryEditor<HostOS::kMacOS>::exec_first(Address va) noexcept {
            auto old = this->first_execution_va();

            if (this->has_global_init()) {
                this->first_global_init(va);
            } else {
                auto &segment_cmd = *this->text_section_.segment();
                this->bin_->main_command()->entrypoint(
                    va - segment_cmd.virtual_address());
            }

            return old;
        }

        Error CustomBinaryEditor<HostOS::kMacOS>::inject_section(
            const std::string &name, const RawCode &content) noexcept {
            if (this->has_section_impl(name)) {
                return Error::kSectionAlreadyExists;
            }

            // create the new section with the generated code inside
            LIEF::MachO::Section section(kSectionPrefix + name,
                                         {content.begin(), content.end()});

            // say that the new section contains executable code
            section +=
                LIEF::MachO::MACHO_SECTION_FLAGS::S_ATTR_SOME_INSTRUCTIONS;
            section +=
                LIEF::MachO::MACHO_SECTION_FLAGS::S_ATTR_PURE_INSTRUCTIONS;

            this->bin_->add_section(section);

            return Error::kNone;
        }

        CustomBinaryEditor<HostOS::kMacOS>::CustomBinaryEditor(
            std::unique_ptr<LIEF::MachO::Binary> &&bin,
            LIEF::MachO::Section &text_section) noexcept
            : bin_{std::move(bin)}, text_section_{text_section} {}

        std::unique_ptr<BinaryEditor<CustomBinaryEditor<HostOS::kMacOS>>>
        CustomBinaryEditor<HostOS::kMacOS>::check_and_init(
            std::unique_ptr<LIEF::MachO::Binary> &&bin) {
            if (bin == nullptr || bin->header().abstract_object_type() !=
                                      LIEF::OBJECT_TYPES::TYPE_EXECUTABLE) {
                return nullptr;
            }

            auto *text_sect = bin->get_section(kSectionPrefix + "text");

            if (text_sect == nullptr) {
                return nullptr;
            }

            std::unique_ptr<BinaryEditor<CustomBinaryEditor<HostOS::kMacOS>>>
                editor(new CustomBinaryEditor<HostOS::kMacOS>(std::move(bin),
                                                              *text_sect));

            return editor;
        }

        bool
        CustomBinaryEditor<HostOS::kMacOS>::has_global_init() const noexcept {
            return this->has_section_impl("mod_init_func") &&
                   this->get_section_impl("mod_init_func")->size() > 0;
        }

        Address
        CustomBinaryEditor<HostOS::kMacOS>::first_global_init() const noexcept {
            if (!this->has_global_init()) {
                return 0;
            }

            Address result = *reinterpret_cast<Address *>(
                this->get_section_content("mod_init_func").data());

            return result;
        }

        Error CustomBinaryEditor<HostOS::kMacOS>::first_global_init(
            Address va) noexcept {
            if (!this->has_global_init()) {
                return Error::kSectionNotFound;
            }

            auto *global_init_sect = this->get_section_impl("mod_init_func");

            bin_->patch_address(global_init_sect->virtual_address(), va,
                                kByteWordSize, LIEF::Binary::VA_TYPES::VA);

            return Error::kNone;
        }

    } // namespace impl

} // namespace poly