#include <algorithm>
#include <string>
#include <vector>

#include <LIEF/LIEF.hpp>
#include <catch2/catch.hpp>

#include <engine/binary_editor.hpp>
#include <engine/host_properties.hpp>

TEST_CASE("Modify the structure of a binary", "[unit][binary_editor]") {
    const std::string hello_world_bin =
        poly::kOS == poly::HostOS::kWindows ? "hello_world.exe" : "hello_world";
    auto be = poly::OsBinaryEditor::build(hello_world_bin);

    SECTION("Inject a section") {

        SECTION("Inject an existing section") {
            const std::string section_name = "data";
            const std::size_t size = 50;
            std::vector<std::uint8_t> data(size, 0xAA);
            auto res = be->inject_section(section_name, data);

            REQUIRE(res == poly::Error::kSectionAlreadyExists);
        }

        SECTION("Inject a new section") {
            std::string section_name = "new";
            const std::size_t size = 10000;
            std::vector<std::uint8_t> data(size, 0xAA);

            auto res = be->inject_section(section_name, data);
            CHECK(res == poly::Error::kNone);

            be->save_changes();

#if defined(POLY_WINDOWS)
            auto bin = LIEF::PE::Parser::parse(hello_world_bin);
            section_name = "." + section_name;
#elif defined(POLY_MACOS)
            auto bin = LIEF::MachO::Parser::parse(hello_world_bin)
                           ->take(LIEF::MachO::CPU_TYPES::CPU_TYPE_X86_64);
            section_name = "__" + section_name;
#elif defined(POLY_LINUX)
            auto bin = LIEF::ELF::Parser::parse(hello_world_bin);
            section_name = "." + section_name;
#endif

            auto section =
                std::find_if(bin->sections().begin(), bin->sections().end(),
                             [section_name](const LIEF::Section &s) {
                                 return s.name() == section_name;
                             });

            REQUIRE(section != bin->sections().end());
            REQUIRE(section->size() >= size);
            REQUIRE_THAT(std::vector<std::uint8_t>(section->content().begin(),
                                                   section->content().end()),
                         Catch::Matchers::Contains(data));
        }
    }

    SECTION("Update the content of a section") {
        SECTION("Update section that doesn't exists") {
            const std::string section_name = "cannot_exist";
            const std::size_t size = 50;
            std::vector<std::uint8_t> data(size, 0xAA);
            auto res = be->update_content(section_name, data);

            REQUIRE(res == poly::Error::kSectionNotFound);
        }

        SECTION("Update existing section") {
            std::string section_name = "data";
            const std::size_t size = GENERATE(50, 10000);
            std::vector<std::uint8_t> data(size, 0xAA);

            auto res = be->update_content(section_name, data);
            CHECK(res == poly::Error::kNone);

            be->save_changes();

#if defined(POLY_WINDOWS)
            auto bin = LIEF::PE::Parser::parse(hello_world_bin);
            section_name = "." + section_name;
#elif defined(POLY_MACOS)
            auto bin = LIEF::MachO::Parser::parse(hello_world_bin)
                           ->take(LIEF::MachO::CPU_TYPES::CPU_TYPE_X86_64);
            section_name = "__" + section_name;
#elif defined(POLY_LINUX)
            auto bin = LIEF::ELF::Parser::parse(hello_world_bin);
            section_name = "." + section_name;
#endif

            auto section =
                std::find_if(bin->sections().begin(), bin->sections().end(),
                             [section_name](const LIEF::Section &s) {
                                 return s.name() == section_name;
                             });

            REQUIRE(section != bin->sections().end());
            REQUIRE(section->size() >= size);
            REQUIRE_THAT(std::vector<std::uint8_t>(section->content().begin(),
                                                   section->content().end()),
                         Catch::Matchers::Contains(data));
        }
    }
}