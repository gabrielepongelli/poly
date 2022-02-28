#include <algorithm>
#include <string>
#include <vector>

#include <LIEF/LIEF.hpp>
#include <catch2/catch.hpp>

#include <engine/binary_editor.hpp>
#include <engine/host_properties.hpp>

TEST_CASE("inject section into a binary", "[unit][binary_editor]") {
    const std::string hello_world_bin =
        poly::kOS == poly::HostOS::kWindows ? "hello_world.exe" : "hello_world";
    poly::BinaryEditor *be = new poly::SpecificBinaryEditor(hello_world_bin);

    SECTION("inject a section") {

        SECTION("inject an existing section") {
#if defined(POLY_WINDOWS)
            const std::string section_name = ".data";
#elif defined(POLY_MACOS)
            const std::string section_name = "__data";
#elif defined(POLY_LINUX)
            const std::string section_name = ".data";
#endif
            const std::size_t size = 50;
            std::vector<std::uint8_t> data(size, 0xAA);
            auto res = be->inject_section(section_name, data);

            REQUIRE(res == poly::BinaryEditorError::kSectionAlreadyExists);
        }

        SECTION("inject a new section") {
            const std::string section_name = GENERATE("new", "");

            const std::size_t size = 10000;

            std::vector<std::uint8_t> data(size, 0xAA);

            auto res = be->inject_section(section_name, data);

            CHECK(res == poly::BinaryEditorError::kNone);

            be->save_changes();

#if defined(POLY_WINDOWS)
            auto bin = LIEF::PE::Parser::parse(hello_world_bin);
#elif defined(POLY_MACOS)
            auto bin = LIEF::MachO::Parser::parse(hello_world_bin)
                           ->take(LIEF::MachO::CPU_TYPES::CPU_TYPE_X86_64);
#elif defined(POLY_LINUX)
            auto bin = LIEF::ELF::Parser::parse(hello_world_bin);
#endif

            auto section =
                std::find_if(bin->sections().begin(), bin->sections().end(),
                             [section_name](const LIEF::Section &s) {
                                 return s.name() == section_name;
                             });

            REQUIRE(section != bin->sections().end());
            REQUIRE(section->content().size() == size);
            REQUIRE_THAT(section->content(), Catch::Matchers::Equals(data));
        }
    }

    SECTION("update the content of a section") {
        SECTION("update section that doesn't exists") {
            const std::string section_name = "cannot_exist";
            const std::size_t size = 50;
            std::vector<std::uint8_t> data(size, 0xAA);
            auto res = be->update_content(section_name, data);

            REQUIRE(res == poly::BinaryEditorError::kSectionNotFound);
        }

        SECTION("update existing section") {
#if defined(POLY_WINDOWS)
            const std::string section_name = ".data";
#elif defined(POLY_MACOS)
            const std::string section_name = "__data";
#elif defined(POLY_LINUX)
            const std::string section_name = ".data";
#endif

            const std::size_t size = GENERATE(50, 10000);
            std::vector<std::uint8_t> data(size, 0xAA);
            auto res = be->update_content(section_name, data);

            CHECK(res == poly::BinaryEditorError::kNone);

            be->save_changes();

#if defined(POLY_WINDOWS)
            auto bin = LIEF::PE::Parser::parse(hello_world_bin);
#elif defined(POLY_MACOS)
            auto bin = LIEF::MachO::Parser::parse(hello_world_bin)
                           ->take(LIEF::MachO::CPU_TYPES::CPU_TYPE_X86_64);
#elif defined(POLY_LINUX)
            auto bin = LIEF::ELF::Parser::parse(hello_world_bin);
#endif

            auto section =
                std::find_if(bin->sections().begin(), bin->sections().end(),
                             [section_name](const LIEF::Section &s) {
                                 return s.name() == section_name;
                             });

            REQUIRE(section != bin->sections().end());
            REQUIRE(section->content().size() == size);
            REQUIRE_THAT(section->content(), Catch::Matchers::Equals(data));
        }
    }

    SECTION("replace the entry") {
#if defined(POLY_WINDOWS)
        auto bin = LIEF::PE::Parser::parse(hello_world_bin);
#elif defined(POLY_MACOS)
        auto bin = LIEF::MachO::Parser::parse(hello_world_bin)
                       ->take(LIEF::MachO::CPU_TYPES::CPU_TYPE_X86_64);
#elif defined(POLY_LINUX)
        auto bin = LIEF::ELF::Parser::parse(hello_world_bin);
#endif
        constexpr poly::Address new_entry = 0;

        auto old_entry = bin->entrypoint();

        CHECK(be->replace_entry(new_entry) == old_entry);

        be->save_changes();

#if defined(POLY_WINDOWS)
        bin = LIEF::PE::Parser::parse(hello_world_bin);
#elif defined(POLY_MACOS)
        bin = LIEF::MachO::Parser::parse(hello_world_bin)
                  ->take(LIEF::MachO::CPU_TYPES::CPU_TYPE_X86_64);
#elif defined(POLY_LINUX)
        bin = LIEF::ELF::Parser::parse(hello_world_bin);
#endif

        REQUIRE(new_entry == bin->entrypoint());
    }
}