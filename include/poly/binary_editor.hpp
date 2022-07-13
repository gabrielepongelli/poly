#pragma once

#include <cstdint>

#include <algorithm>
#include <istream>
#include <memory>
#include <string>
#include <vector>

#include <LIEF/LIEF.hpp>

#include "enums.hpp"
#include "filesystem.hpp"
#include "host_properties.hpp"
#include "utils.hpp"

namespace poly {

    //!
    //! Interface that describe an entity that can modify the structure and
    //! the content of a binary and can retrieve some info about its structure.
    //! A class that wants to implement this interface must inherit from its own
    //! template specialization:
    //! \code
    //!      class Impl : public BinaryEditor<Impl> { ... };
    //! \endcode
    //!
    //! \see poly::CustomBinaryEditor<HostOS::kLinux>
    //! \see poly::CustomBinaryEditor<HostOS::kMacOS>
    //! \see poly::CustomBinaryEditor<HostOS::kWindows>
    //! \see poly::OsBinaryEditor
    //!
    template <class Real>
    class BinaryEditor : public impl::Crtp<Real> {
      public:
        //!
        //! Build a new BinaryEditor.
        //! \param path path of the file to parse.
        //! \returns nullptr if the file in the path specified isn't an
        //! executable binary or if it doesn't have an entry point, otherwise
        //! a valid pointer will be returned.
        //!
        static inline std::unique_ptr<BinaryEditor<Real>>
        build(const fs::path &path) noexcept {
            return std::move(Real::build(path));
        }

        //!
        //! Build a new BinaryEditor.
        //! \param raw raw bytes that make up the binary.
        //! \param path path of the binary. Default to empty.
        //! \returns nullptr if the bytes passed don't represent a valid
        //! executable binary or if it doesn't have an entry point, otherwise a
        //! valid pointer will be returned.
        //!
        static inline std::unique_ptr<BinaryEditor<Real>>
        build(const std::vector<std::uint8_t> &raw,
              const fs::path &path = {}) noexcept {
            return std::move(Real::build(raw, path));
        }

        //!
        //! Build a new BinaryEditor.
        //! \param src input stream from which to read the binary.
        //! \param size the size of the binary in bytes to read. If the stream
        //! is shorter than size, this method tries to parse all the bytes read
        //! until the end.
        //! \param path path of the binary. Default to empty.
        //! \returns nullptr if the bytes read don't represent a valid
        //! executable binary or if it doesn't have an entry point, otherwise a
        //! valid pointer will be returned.
        //!
        static inline std::unique_ptr<BinaryEditor<Real>>
        build(std::istream &src, std::size_t size,
              const fs::path &path = {}) noexcept {
            return std::move(Real::build(src, size, path));
        }

        //!
        //! Align the specified address to the page size.
        //! \param addr address to align.
        //! \param len [in, out] length before the alignement. After the
        //! execution of this function his value represent the new length
        //! calculated after the alignement.
        //! \returns the aligned address.
        //!
        static inline Address align_to_page_size(Address addr,
                                                 std::size_t &len) noexcept {
            return Real::align_to_page_size(addr, len);
        }

        //!
        //! Get the virtual address of the first instruction of this binary that
        //! will be executed.
        //!
        inline Address first_execution_va() const noexcept {
            return this->real()->first_execution_va();
        }

        //!
        //! Modify the binary in order to make it execute first the code stored
        //! in the address specified.
        //! \param va virtual address where the code to execute is stored.
        //! \return the old virtual address that was first run prior to this
        //! change.
        //!
        inline Address exec_first(Address va) noexcept {
            return this->real()->exec_first(va);
        }

        //!
        //! Get the runtime address of the text section of the binary.
        //! \warning The return value of this method is correct only if the
        //! binary is the same being executed by this process.
        //!
        inline Address text_section_ra() const noexcept {
            return this->real()->text_section_ra();
        }

        //!
        //! Get the virtual address of the text section of the binary.
        //!
        inline Address text_section_va() const noexcept {
            return this->real()->text_section_va();
        }

        //!
        //! Get the size in bytes of the text section of the binary.
        //!
        inline std::uint64_t text_section_size() const noexcept {
            return this->real()->text_section_size();
        }

        //!
        //! Get the content of the text section of the binary.
        //!
        inline RawCode text_section_content() const noexcept {
            return this->real()->text_section_content();
        }

        //!
        //! Update the content of the text section.
        //! \warning The previous content will be completely deleted.
        //! \note The size of the resulting section could be bigger than the one
        //! of the content due to the page size in use.
        //! \param content the code that the new section will contain.
        //! \return kNone if no error is raised.
        //!
        inline Error
        update_text_section_content(const RawCode &content) noexcept {
            return this->real()->update_text_section_content(content);
        }

        //!
        //! Modify the binary adding a new section that contain executable
        //! code.
        //! \note The size of the resulting section could be bigger than the one
        //! of the content due to the page size in use.
        //! \param name name of the new section. If a section with this name
        //! already exists it doesn't modify it.
        //! \param content the code that the new section will contain.
        //! \return kNone if no error is raised.
        //!
        inline Error inject_section(const std::string &name,
                                    const RawCode &content) noexcept {
            return this->real()->inject_section(name, content);
        }

        //!
        //! Calculate the virtual address of data contained in the section
        //! specified, at the offset specified.
        //! \param name name of the section.
        //! \param offset offset inside the section.
        //! \param va [out] calculated virtual address.
        //! \return kNone if no error is raised.
        //!
        inline Error
        calculate_va(const std::string &name, Address &va,
                     const std::uint64_t offset = 0) const noexcept {
            return this->real()->calculate_va(name, va, offset);
        }

        //!
        //! Update the content of the section specified.
        //! \warning The previous content will be completely deleted.
        //!
        //! \note The size of the resulting section could be bigger than the one
        //! of the content due to the page size in use.
        //!
        //! \param name name of the section.
        //! \param content the code that the new section will contain.
        //! \return kNone if no error is raised.
        //!
        inline Error update_content(const std::string &name,
                                    const RawCode &content) noexcept {
            return this->real()->update_content(name, content);
        }

        //!
        //! Get the content of the section specified.
        //! \param name name of the section.
        //! \return the raw bytes contained in the section specified. If the
        //! section specified is not present, a raw code of size 0 is
        //! returned.
        //!
        inline RawCode
        get_section_content(const std::string &name) const noexcept {
            return this->real()->get_section_content();
        }

        //!
        //! Reconstruct the binary.
        //! \param path optional path where to save the modified binary. If
        //! is an empty path, the path will be the same of the binary
        //! parsed by this binary editor. Default is empty.
        //! \return true if this method has written additional data (which were
        //! already present in the original binary) after the binary which are
        //! not part of the executable format, otherwise if those data hasn't
        //! been written (or if those data are not present in the original
        //! binary) returns false.
        //!
        inline bool save_changes(const fs::path &path = {}) noexcept {
            return this->real()->save_changes(path);
        }

        //!
        //! Reconstruct the binary.
        //! \param raw [out] raw bytes that will make up the final binary.
        //! \return true if this method has written additional data (which were
        //! already present in the original binary) after the binary which are
        //! not part of the executable format, otherwise if those data hasn't
        //! been written (or if those data are not present in the original
        //! binary) returns false.
        //!
        inline bool save_changes(std::vector<std::uint8_t> &raw) noexcept {
            return this->real()->save_changes(raw);
        }

        //!
        //! Reconstruct the binary.
        //! \param dst output stream where to write the final binary.
        //! \return true if this method has written additional data (which were
        //! already present in the original binary) after the binary which are
        //! not part of the executable format, otherwise if those data hasn't
        //! been written (or if those data are not present in the original
        //! binary) returns false.
        //!
        inline bool save_changes(std::ostream &dst) noexcept {
            return this->real()->save_changes(dst);
        }
    };

    namespace impl {

        template <poly::HostOS O>
        struct Binary : LIEF::Binary {};

        using OsBinary = Binary<kOS>;

        template <poly::HostOS O>
        struct Section : LIEF::Section {};

        using OsSection = Section<kOS>;

    } // namespace impl

    //!
    //! Abstract class which implements all the common functionalities of
    //! the BinaryEditor interface.
    //!
    //! \internal
    //! It requires to the concrete class that
    //! extends it to implement the following protected member methods:
    //! - ```bool has_section_impl(const std::string &name) const noexcept```
    //! - ```poly::impl::OsSection * get_section_impl(const std::string &name)
    //! noexcept```
    //! - ```const poly::impl::OsSection * get_section_impl(
    //!                          const std::string &name) const noexcept```
    //! - ```poly::impl::OsSection &get_text_section_impl() noexcept```
    //! - ```const poly::impl::OsSection &get_text_section_impl() const
    //! noexcept```
    //! - ```poly::impl::OsBinary &get_bin_impl() noexcept```
    //! - ```const poly::impl::OsBinary &get_bin_impl() const noexcept```
    //! - ```Address get_entry_point_ra_impl() const noexcept```
    //! It also requires to the concrete class that extends it to define the
    //! protected static members:
    //! - ```static constexpr Address kPageSize_```
    //! - ```static const std::string kSectionPrefix_```
    //! \endinternal
    //!
    template <class Real>
    class CommonBinaryEditor : public BinaryEditor<Real> {
      public:
        static std::unique_ptr<BinaryEditor<Real>>
        build(std::istream &src, std::size_t size,
              const fs::path &path) noexcept;

        static Address align_to_page_size(Address addr,
                                          std::size_t &len) noexcept;

        Address text_section_ra() const noexcept;

        Address text_section_va() const noexcept;

        std::uint64_t text_section_size() const noexcept;

        RawCode text_section_content() const noexcept;

        Error update_text_section_content(const RawCode &content) noexcept;

        Error calculate_va(const std::string &name, Address &va,
                           const std::uint64_t offset = 0) const noexcept;

        Error update_content(const std::string &name,
                             const RawCode &content) noexcept;

        RawCode get_section_content(const std::string &name) const noexcept;

        bool save_changes(std::ostream &dst) noexcept;

      protected:
        //!
        //! \private
        //! \internal
        //! \public
        //!
        //! Structure needed to access the protected methods implemented by
        //! the final concrete class.
        //!
        struct ProtectedAccessor : public Real {

            //!
            //! Check whether the binary contains a section with the name
            //! specified.
            //! \param real instance of the final concrete BinaryEditor
            //! implementation.
            //! \param name name of the section.
            //!
            static bool has_section(const Real &real,
                                    const std::string &name) noexcept;

            //!
            //! Retrieve the section with the name specified.
            //! \param real instance of the final concrete BinaryEditor
            //! implementation.
            //! \param name name of the section.
            //! \return a valid pointer if the section is present in the
            //! binary, nullptr otherwise.
            //!
            static impl::OsSection *
            get_section(Real &real, const std::string &name) noexcept;
            static const impl::OsSection *
            get_section(const Real &real, const std::string &name) noexcept;

            //!
            //! Retrieve the text section of the binary.
            //! \param real instance of the final concrete BinaryEditor
            //! implementation.
            //!
            static impl::OsSection &get_text_section(Real &real) noexcept;
            static const impl::OsSection &
            get_text_section(const Real &real) noexcept;

            //!
            //! Retrieve the in-memory representation of the binary.
            //! \param real instance of the final concrete BinaryEditor
            //! implementation.
            //!
            static impl::OsBinary &get_bin(Real &real) noexcept;
            static const impl::OsBinary &get_bin(const Real &real) noexcept;

            //!
            //! Retrieve the runtime address of binary's entry point.
            //! \param real instance of the final concrete BinaryEditor
            //! implementation.
            //!
            static Address get_entry_point_ra(const Real &real) noexcept;

            static constexpr Address kPageSize = Real::kPageSize_;
            static constexpr const std::string &kSectionPrefix =
                Real::kSectionPrefix_;
        };
    };

    //!
    //! Generic implementation for not supported operating systems. In order
    //! to support an os, a specialization for the appropriate HostOS value
    //! must be provided.
    //!
    template <HostOS OS = HostOS::kNotSupported>
    class CustomBinaryEditor
        : public CommonBinaryEditor<CustomBinaryEditor<OS>> {
        static_assert(OS != HostOS::kNotSupported, "");
    };

    //!
    //! \typedef OsBinaryEditor
    //!
    //! BinaryEditor implementation. This class will automatically be resolved
    //! to the specific BinaryEditor implementation to use for the current
    //! operating system.
    //!
    //! \see poly::CustomBinaryEditor<HostOS::kLinux>
    //! \see poly::CustomBinaryEditor<HostOS::kMacOS>
    //! \see poly::CustomBinaryEditor<HostOS::kWindows>
    //!
    using OsBinaryEditor = CustomBinaryEditor<kOS>;

} // namespace poly

#include "binary_editor.tpp"