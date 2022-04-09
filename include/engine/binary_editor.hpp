#pragma once

#include <cstdint>

#include <memory>
#include <string>
#include <vector>

#include <LIEF/LIEF.hpp>

#include "enums.hpp"
#include "host_properties.hpp"
#include "utils.hpp"

namespace poly {

    /**
     * Interface that describe an entity that can modify the structure and the
     * content of a binary and can retrieve some infos about it.
     */
    template <class RealEditor>
    class BinaryEditorInterface : public impl::Crtp<RealEditor> {
      public:
        /**
         * Get the virtual address of the actual entry point of the binary.
         */
        inline Address entry_point() const noexcept {
            return this->real()->entry_point();
        }

        /**
         * Get the runtime address of the text section of the binary.
         * Warning: the return value of this method is correct only if the
         * binary is the same being executed by this process.
         */
        inline Address text_section_ra() const noexcept {
            return this->real()->text_section_ra();
        }

        /**
         * Get the virtual address of the text section of the binary.
         */
        inline Address text_section_va() const noexcept {
            return this->real()->text_section_va();
        }

        /**
         * Get the size in bytes of the text section of the binary.
         */
        inline std::uint64_t text_section_size() const noexcept {
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
        inline Error inject_section(const std::string &name,
                                    const RawCode &content) noexcept {
            return this->real()->inject_section(name, content);
        }

        /**
         * Replace the entry of the binary with a new one.
         * @param new_entry virtual address of the new entry point.
         * @return the old entry point
         */
        inline Address replace_entry(Address new_entry) noexcept {
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
        inline Error
        calculate_va(const std::string &name, Address &va,
                     const std::uint64_t offset = 0) const noexcept {
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
        inline Error update_content(const std::string &name,
                                    const RawCode &content) noexcept {
            return this->real()->update_content(name, content);
        }

        /**
         * Write the changes on the executable.
         */
        inline void save_changes() noexcept { this->real()->save_changes(); }
    };

    namespace impl {

        template <poly::HostOS O>
        struct Binary : LIEF::Binary {};

        template <poly::HostOS O>
        struct Section : LIEF::Section {};

    } // namespace impl

    template <HostOS OS>
    class CommonBinaryEditor
        : public BinaryEditorInterface<CommonBinaryEditor<OS>> {
      public:
        static_assert(OS != HostOS::kNotSupported,
                      "This operating system is not supported.");

        /**
         * Build a new BinaryEditor.
         * @param path path of the file to parse.
         * @returns nullptr if the file in the path specified isn't an
         * executable program or it doesn't have an entry point, otherwise a
         * valid pointer will be returned.
         */
        static std::unique_ptr<BinaryEditorInterface<CommonBinaryEditor<OS>>>
        build(const std::string &path) noexcept;

        Address entry_point() const noexcept;

        Address text_section_ra() const noexcept;

        Address text_section_va() const noexcept;

        std::uint64_t text_section_size() const noexcept;

        Error inject_section(const std::string &name,
                             const RawCode &content) noexcept;

        Address replace_entry(Address new_entry) noexcept;

        Error calculate_va(const std::string &name, Address &va,
                           const std::uint64_t offset = 0) const noexcept;

        Error update_content(const std::string &name,
                             const RawCode &content) noexcept;

        void save_changes() noexcept;

      protected:
        CommonBinaryEditor(std::unique_ptr<impl::Binary<OS>> &&bin,
                           impl::Section<OS> *text_section,
                           Address entry_va) noexcept;

      private:
        static std::unique_ptr<impl::Binary<OS>>
        parse_bin(const std::string name) noexcept;

        static impl::Section<OS> *
        get_text_section(impl::Binary<OS> &bin) noexcept;

        static Address
        get_entry_point_va(impl::Binary<OS> &bin,
                           impl::Section<OS> &text_sect) noexcept;

        bool has_section(const std::string &name) const noexcept;

        impl::Section<OS> *get_section(const std::string &name) const noexcept;

        std::unique_ptr<impl::Section<OS>>
        create_new_section(const std::string &name,
                           const RawCode &content) noexcept;

        std::unique_ptr<impl::Binary<OS>> bin_;
        impl::Section<OS> *text_section_;
        Address entry_point_va_;
    };

    using OsBinaryEditor = CommonBinaryEditor<kOS>;
    using BinaryEditor = BinaryEditorInterface<OsBinaryEditor>;

} // namespace poly

#include "binary_editor.tpp"