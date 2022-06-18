#include <catch2/catch.hpp>

#include <cstdlib>

#include <algorithm>
#include <fstream>
#include <limits>
#include <string>
#include <vector>

#include <LIEF/LIEF.hpp>
#include <asmjit/asmjit.h>

#include <poly/binary_editor.hpp>
#include <poly/filesystem.hpp>
#include <poly/host_properties.hpp>

#if defined(POLY_MACOS)
poly::RawCode generate_code(poly::OsBinaryEditor &, int return_code,
                            poly::Address) {
    asmjit::CodeHolder code{};
    code.init(asmjit::Environment::host());
    asmjit::x86::Assembler a{&code};

    a.mov(a.zax(), 0x2000001);
    a.mov(a.zdi(), return_code);
    a.syscall();

    code.flatten();
    unsigned char *buffer = new unsigned char[code.codeSize()];
    code.copyFlattenedData(buffer, code.codeSize());

    return {buffer, code.codeSize()};
}
#elif defined(POLY_WINDOWS)
poly::RawCode generate_code(poly::OsBinaryEditor &be, int return_code,
                            poly::Address va) {
    asmjit::CodeHolder code{};
    code.init(asmjit::Environment::host());
    asmjit::x86::Assembler a{&code};

    asmjit::x86::Mem GetCurrentProcess_va(
        be.get_imported_function_va("KERNEL32.dll", "GetCurrentProcess"));
    GetCurrentProcess_va.setRel();

    asmjit::x86::Mem TerminateProcess_va(
        be.get_imported_function_va("KERNEL32.dll", "TerminateProcess"));
    TerminateProcess_va.setRel();

    a.mov(a.zax(), GetCurrentProcess_va);
    a.call(a.zax());

    a.mov(a.zcx(), a.zax());
    a.mov(a.zdx(), return_code);
    a.mov(a.zax(), TerminateProcess_va);
    a.call(a.zax());

    code.flatten();
    code.relocateToBase(va);
    unsigned char *buffer = new unsigned char[code.codeSize()];
    code.copyFlattenedData(buffer, code.codeSize());

    return {buffer, code.codeSize()};
}
#else
poly::RawCode generate_code(poly::OsBinaryEditor &, int return_code,
                            poly::Address) {
    asmjit::CodeHolder code{};
    code.init(asmjit::Environment::host());
    asmjit::x86::Assembler a{&code};

    a.mov(a.zax(), 60);
    a.mov(a.zdi(), return_code);
    a.syscall();

    code.flatten();
    unsigned char *buffer = new unsigned char[code.codeSize()];
    code.copyFlattenedData(buffer, code.codeSize());

    return {buffer, code.codeSize()};
}
#endif

using TestEditor = poly::BinaryEditor<poly::OsBinaryEditor>;

using Rand32BitGen = Catch::Generators::RandomIntegerGenerator<int>;

inline int get(Rand32BitGen &gen) {
    auto res = gen.get();
    gen.next();
    return res;
}

TEST_CASE("Modify the structure of a binary", "[unit][binary_editor]") {

    const std::string hello_world_bin =
        poly::kOS == poly::HostOS::kWindows ? "hello_world.exe" : "hello_world";
    const std::string test_bin = "test_" + hello_world_bin;

    SECTION("Parse the binary") {

        SECTION("Parse from path") {

            SECTION("Pass a valid executable's path") {
                auto res = TestEditor::build(hello_world_bin);
                REQUIRE(res != nullptr);

                res.release();
            }

            SECTION("Pass an invalid path") {
                auto res = TestEditor::build("");
                REQUIRE(res == nullptr);
            }

            SECTION("Pass a path to an invalid file") {
                const std::string text_file = "text_file.txt";

                std::ofstream target{text_file, std::ios::out};
                target << "Test";
                target.close();

                auto res = TestEditor::build(text_file);
                REQUIRE(res == nullptr);

                poly::fs::remove(text_file);
            }
        }

        SECTION("Parse from stream") {
            const auto size = poly::fs::file_size(hello_world_bin);
            std::ifstream target{hello_world_bin,
                                 std::ios::in | std::ios::binary};

            auto res = TestEditor::build(target, size);
            REQUIRE(res != nullptr);

            res.release();
            target.close();
        }
    }

    SECTION("Modify and inspect the binary") {

        auto be = TestEditor::build(hello_world_bin);

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

                be->save_changes(test_bin);

#if defined(POLY_WINDOWS)
                auto bin = LIEF::PE::Parser::parse(test_bin);
                section_name = "." + section_name;
#elif defined(POLY_MACOS)
                auto bin = LIEF::MachO::Parser::parse(test_bin)->take(
                    LIEF::MachO::CPU_TYPES::CPU_TYPE_X86_64);
                section_name = "__" + section_name;
#elif defined(POLY_LINUX)
                auto bin = LIEF::ELF::Parser::parse(test_bin);
                section_name = "." + section_name;
#endif

                auto section =
                    std::find_if(bin->sections().begin(), bin->sections().end(),
                                 [section_name](const LIEF::Section &s) {
                                     return s.name() == section_name;
                                 });

                REQUIRE(section != bin->sections().end());
                REQUIRE(section->size() >= size);
                REQUIRE_THAT(
                    std::vector<std::uint8_t>(section->content().begin(),
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

                be->save_changes(test_bin);

#if defined(POLY_WINDOWS)
                auto bin = LIEF::PE::Parser::parse(test_bin);
                section_name = "." + section_name;
#elif defined(POLY_MACOS)
                auto bin = LIEF::MachO::Parser::parse(test_bin)->take(
                    LIEF::MachO::CPU_TYPES::CPU_TYPE_X86_64);
                section_name = "__" + section_name;
#elif defined(POLY_LINUX)
                auto bin = LIEF::ELF::Parser::parse(test_bin);
                section_name = "." + section_name;
#endif

                auto section =
                    std::find_if(bin->sections().begin(), bin->sections().end(),
                                 [section_name](const LIEF::Section &s) {
                                     return s.name() == section_name;
                                 });

                REQUIRE(section != bin->sections().end());
                REQUIRE(section->size() >= size);
                REQUIRE_THAT(
                    std::vector<std::uint8_t>(section->content().begin(),
                                              section->content().end()),
                    Catch::Matchers::Contains(data));
            }
        }
    }

    SECTION("Modify normal execution flow") {
        const std::string section_name = "test";

        auto be = TestEditor::build(hello_world_bin);
        auto gen = Rand32BitGen(1, 255);

        REQUIRE(be->inject_section(section_name, {}) == poly::Error::kNone);
        poly::Address section_va;
        REQUIRE(be->calculate_va(section_name, section_va) ==
                poly::Error::kNone);

        auto rand_return_code = get(gen);
        auto code = generate_code(static_cast<poly::OsBinaryEditor &>(*be),
                                  rand_return_code, section_va);

        REQUIRE(be->update_content(section_name, code) == poly::Error::kNone);

        be->exec_first(section_va);
        be->save_changes(test_bin);

        REQUIRE(poly::fs::exists(test_bin));

        poly::fs::permissions(test_bin, poly::fs::perms::owner_exec,
                              poly::fs::perm_options::add);

        std::string cmd = "";
        cmd = "./" + test_bin;
        if (poly::kOS == poly::HostOS::kWindows) {
            cmd = cmd.replace(1, 1, "\\");
        }
        int res = std::system(cmd.c_str());

#ifndef POLY_WINDOWS
        res = WEXITSTATUS(res);
#endif
        REQUIRE(res == rand_return_code);
    }

    if (poly::fs::exists(test_bin)) {
        poly::fs::remove(test_bin);
    }
}