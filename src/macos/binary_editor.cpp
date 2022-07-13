#include "poly/macos/binary_editor.hpp"

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

    const std::string CustomBinaryEditor<HostOS::kMacOS>::kSectionPrefix_ =
        "__";

    const std::string CustomBinaryEditor<HostOS::kMacOS>::kNewSegmentName_ =
        CustomBinaryEditor<HostOS::kMacOS>::kSectionPrefix_ + "NEW";

    std::unique_ptr<BinaryEditor<CustomBinaryEditor<HostOS::kMacOS>>>
    CustomBinaryEditor<HostOS::kMacOS>::build(const fs::path &path) noexcept {
        auto fat_bin = LIEF::MachO::Parser::parse(path.string());

        if (fat_bin == nullptr) {
            return nullptr;
        }

        return check_and_init(
            fat_bin->take(LIEF::MachO::CPU_TYPES::CPU_TYPE_X86_64));
    }

    std::unique_ptr<BinaryEditor<CustomBinaryEditor<HostOS::kMacOS>>>
    CustomBinaryEditor<HostOS::kMacOS>::build(
        const std::vector<std::uint8_t> &raw, const fs::path &path) noexcept {
        auto bin = LIEF::MachO::Parser::parse(raw, path.string())
                       ->take(LIEF::MachO::CPU_TYPES::CPU_TYPE_X86_64);

        return check_and_init(std::move(bin));
    }

    Address
    CustomBinaryEditor<HostOS::kMacOS>::first_execution_va() const noexcept {
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

        auto *segment = bin_->get_segment(kNewSegmentName_);
        if (segment == nullptr) {
            LIEF::MachO::SegmentCommand seg_cmd{kNewSegmentName_};
            seg_cmd.max_protection(0x5);
            seg_cmd.init_protection(0x5);
            segment = static_cast<LIEF::MachO::SegmentCommand *>(
                this->bin_->add(seg_cmd));
        }

        // calculate the total size of the sections (with the new one)
        std::size_t sizeof_all_sections = content.size();
        for (auto &s : segment->sections()) {
            sizeof_all_sections += s.size();
        }

        // create the new section
        LIEF::MachO::Section section(kSectionPrefix_ + name);
        section.virtual_address(segment->virtual_address() +
                                sizeof_all_sections - content.size());
        section.offset(segment->file_offset() + sizeof_all_sections -
                       content.size());
        section.alignment(this->text_section_.alignment());
        section += LIEF::MachO::MACHO_SECTION_FLAGS::S_ATTR_SOME_INSTRUCTIONS;
        section += LIEF::MachO::MACHO_SECTION_FLAGS::S_ATTR_PURE_INSTRUCTIONS;

        auto *added_section = this->bin_->add_section(*segment, section);

        // if not enough space or if the segment has just been created
        // extends it
        if (segment->file_size() == 0 ||
            segment->file_size() < sizeof_all_sections) {
            auto seg_file_size = segment->file_size();
            std::size_t new_size = seg_file_size + content.size();
            if (new_size < kSegmentMinSize_) {
                new_size = kSegmentMinSize_;
            } else {
                auto additional_data = new_size % kPageSize_;
                new_size +=
                    additional_data > 0 ? kPageSize_ - additional_data : 0;
            }

            std::vector<std::uint8_t> data(new_size, 0);
            std::copy(segment->content().begin(), segment->content().end(),
                      data.begin());
            segment->file_size(data.size());
            segment->virtual_size(data.size());
            segment->content(data);

            // since this segment will be located right before the
            // __LINKEDIT segment (which is the last one), the only thing
            // to do is to shift it to make space for the new data
            this->bin_->shift_linkedit(data.size() - seg_file_size);
        }

        // add the content to the newly created section and update its size
        if (content.size() > 0) {
            added_section->size(content.size());
            added_section->content(
                std::vector<std::uint8_t>(content.begin(), content.end()));
        }

        return Error::kNone;
    }

    Error CustomBinaryEditor<HostOS::kMacOS>::update_content(
        const std::string &name, const RawCode &content) noexcept {
        if (!this->has_section_impl(name)) {
            return Error::kSectionNotFound;
        }

        auto *section = this->get_section_impl(name);
        auto *segment = section->segment();

        if (section->size() < content.size()) {
            auto section_size_offset = content.size() - section->size();

            // calculate the total size of the sections (with the updated
            // size of the new one)
            std::size_t sizeof_all_sections = section_size_offset;
            for (auto &s : segment->sections()) {
                sizeof_all_sections += s.size();
            }

            if (segment->file_size() < sizeof_all_sections) {
                // align offset to page size
                auto segment_offset =
                    sizeof_all_sections - segment->file_size();
                auto extra_len = segment_offset % kPageSize_;
                if (extra_len > 0) {
                    segment_offset += kPageSize_ - extra_len;
                }

                this->bin_->extend_segment(*segment, segment_offset);
            }

            // shift all the sections placed after the modified one
            for (auto &s : segment->sections()) {
                if (s.offset() > section->offset()) {
                    s.offset(s.offset() + section_size_offset);
                    s.virtual_address(s.virtual_address() +
                                      section_size_offset);
                }
            }
        } else {
            section->clear(0);
        }

        // add the modified content to the section and update its size
        section->size(content.size());
        section->content(
            std::vector<std::uint8_t>(content.begin(), content.end()));

        return Error::kNone;
    }

    std::uint8_t CustomBinaryEditor<HostOS::kMacOS>::code_max_permissions(
        std::uint8_t perms) noexcept {
        auto old = this->code_max_permissions();

        this->text_section_.segment()->max_protection(perms & 0x7);

        return old;
    }

    bool CustomBinaryEditor<HostOS::kMacOS>::save_changes(
        const fs::path &path) noexcept {
        if (path.empty()) {
            this->bin_->write(this->bin_->name());
        } else {
            this->bin_->write(path.string());
        }

        return false;
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

        auto *text_sect = bin->get_section(kSectionPrefix_ + "text");

        if (text_sect == nullptr) {
            return nullptr;
        }

        std::unique_ptr<BinaryEditor<CustomBinaryEditor<HostOS::kMacOS>>>
            editor(new CustomBinaryEditor<HostOS::kMacOS>(std::move(bin),
                                                          *text_sect));

        return editor;
    }

    bool CustomBinaryEditor<HostOS::kMacOS>::has_global_init() const noexcept {
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

    Error
    CustomBinaryEditor<HostOS::kMacOS>::first_global_init(Address va) noexcept {
        if (!this->has_global_init()) {
            return Error::kSectionNotFound;
        }

        auto *global_init_sect = this->get_section_impl("mod_init_func");

        bin_->patch_address(global_init_sect->virtual_address(), va,
                            kByteWordSize, LIEF::Binary::VA_TYPES::VA);

        return Error::kNone;
    }

} // namespace poly