#pragma once

#include <cstdint>

#include <memory>
#include <string>
#include <vector>

#include <LIEF/LIEF.hpp>

#include "code_container.hpp"
#include "enums.hpp"
#include "host_properties.hpp"
#include "utils.hpp"

namespace poly {

    /**
     * Interface that describe something that can modify a binary and retrieve
     * some infos about it.
     */
    template <class RealEditor>
    class BinaryEditorInterface : public impl::crtp_single_param<RealEditor> {
      public:
        /**
         * Get the virtual address of the actual entry point of the binary.
         */
        Address entry_point() { return this->real()->entry_point(); }

        /**
         * Get the runtime address of the text section of the binary.
         * Warning: the return value of this method is correct only if the
         * binary is the same being executed by this process.
         */
        Address text_section_ra() { return this->real()->text_section_ra(); }

        /**
         * Get the virtual address of the text section of the binary.
         */
        Address text_section_va() { return this->real()->text_section_va(); }

        /**
         * Get the size in bytes of the text section of the binary.
         */
        std::uint64_t text_section_size() {
            return this->real()->text_section_size();
        }

        /**
         * Modify the binary adding a new section that contain executable code.
         * @param name name of the new section. If a section with this name
         * already exists it doesn't modify it. NOTE: the size of the resulting
         * section could be bigger than the one of the content due to the page
         * size in use.
         * @param content the code that the new section will contain.
         * @return kNone if no error is raised.
         */
        BinaryEditorError inject_section(const std::string &name,
                                         const ExecutableCode &content) {
            return this->real()->inject_section(name, content);
        }

        BinaryEditorError
        inject_section(const std::string &name,
                       const std::vector<std::uint8_t> &content) {
            return this->real()->inject_section(name, content);
        }

        /**
         * Replace the entry of the binary with a new one.
         * @param new_entry virtual address of the new entry point.
         * @return the old entry point
         */
        Address replace_entry(Address new_entry) {
            return this->real()->replace_entry(new_entry);
        }

        /**
         * Calculate the virtual address of data contained in the section
         * specified, at the offset specified.
         * @param name name of the section.
         * @param offset offset inside the section.
         * @param va [out] calculated virtual address.
         * @return kNone if no error is raised.
         */
        BinaryEditorError calculate_va(const std::string &name, Address &va,
                                       const std::uint64_t offset = 0) {
            return this->real()->calculate_va(name, offset, va);
        }

        /**
         * Update the content of the section specified. WARNING: the previous
         * content will be completely deleted. NOTE: the size of the resulting
         * section could be bigger than the one of the content due to the page
         * size in use.
         * @param name name of the section.
         * @param content the code that the new section will contain.
         * @return kNone if no error is raised.
         */
        BinaryEditorError
        update_content(const std::string &name,
                       const std::vector<std::uint8_t> &content) {
            return this->real()->update_content(name, content);
        }

        BinaryEditorError update_content(const std::string &name,
                                         const ExecutableCode &content) {
            return this->real()->update_content(name, content);
        }

        /**
         * Write the changes on the executable.
         */
        void save_changes() { this->real()->save_changes(); }
    };

    namespace impl {

        template <poly::HostOS O>
        struct Binary : LIEF::Binary {};

        template <poly::HostOS O>
        struct Section : LIEF::Section {};

    } // namespace impl

    template <HostOS OS = HostOS::kNotSupported>
    class CommonBinaryEditor
        : public BinaryEditorInterface<CommonBinaryEditor<OS>> {
      public:
        CommonBinaryEditor(const std::string name);

        Address entry_point();

        Address text_section_ra();

        Address text_section_va();

        std::uint64_t text_section_size();

        BinaryEditorError inject_section(const std::string &name,
                                         const ExecutableCode &content);

        BinaryEditorError
        inject_section(const std::string &name,
                       const std::vector<std::uint8_t> &content);

        Address replace_entry(Address new_entry);

        BinaryEditorError calculate_va(const std::string &name, Address &va,
                                       const std::uint64_t offset = 0);

        BinaryEditorError
        update_content(const std::string &name,
                       const std::vector<std::uint8_t> &content);

        BinaryEditorError update_content(const std::string &name,
                                         const ExecutableCode &content);

        void save_changes();

      private:
        std::unique_ptr<impl::Binary<OS>> parse_bin(const std::string name);

        impl::Section<OS> *get_text_section();

        Address get_entry_point_va();

        bool has_section(const std::string &name);

        impl::Section<OS> *get_section(const std::string &name);

        std::unique_ptr<impl::Section<OS>>
        create_new_section(const std::string &name, const std::uint8_t *content,
                           std::uint64_t size);

        std::unique_ptr<impl::Binary<OS>> bin_;
        impl::Section<OS> *text_section_;
        Address entry_point_va_;
    };

    using SpecificBinaryEditor = CommonBinaryEditor<kOS>;
    using BinaryEditor = BinaryEditorInterface<SpecificBinaryEditor>;

} // namespace poly

#include "binary_editor.tpp"