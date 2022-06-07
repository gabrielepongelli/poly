#include <catch2/catch.hpp>

#include <cstdlib>

#include <fstream>
#include <string>

#include <poly/filesystem.hpp>
#include <poly/host_properties.hpp>

using Rand32BitGen = Catch::Generators::RandomIntegerGenerator<int>;

inline int get(Rand32BitGen &gen) {
    auto res = gen.get();
    gen.next();
    return res;
}

poly::fs::path incremental_copy(
    poly::fs::path src, unsigned i,
    poly::fs::copy_options op = poly::fs::copy_options::overwrite_existing) {
    poly::fs::path res{(src.parent_path() / src.stem()).string() +
                       std::to_string(i) + src.extension().string()};

    poly::fs::copy_file(src, res, op);

    return res;
}

TEST_CASE("Infect other binaries", "[virus][integration]") {
    const poly::fs::path virus_bin{poly::kOS == poly::HostOS::kWindows
                                       ? "./virus_test.exe"
                                       : "./virus_test"};
    const poly::fs::path target_bin{poly::kOS == poly::HostOS::kWindows
                                        ? "./file_test.exe"
                                        : "./file_test"};
    const std::string test_file = "test.txt";

    auto target_copy1 = incremental_copy(target_bin, 1);
    auto target_copy2 = incremental_copy(target_bin, 2);

    std::string cmd = "";
    auto size_before = poly::fs::file_size(target_copy1);
    auto perms_before = poly::fs::status(target_copy1).permissions();
    std::string target = target_copy1.string();
    cmd = virus_bin.string() + " " + target;
    auto res = std::system(cmd.c_str());
#ifndef POLY_WINDOWS
    res = WEXITSTATUS(res);
#endif

    REQUIRE(res == 0);
    REQUIRE(poly::fs::exists(target_copy1));
    REQUIRE(size_before < poly::fs::file_size(target_copy1));
    CHECK(perms_before == poly::fs::status(target_copy1).permissions());

    const std::string test_string = "TEST";
    auto gen = Rand32BitGen(2, 255);
    int test_return_value = get(gen);
    cmd = "";
    target = target_copy2.string();
    cmd = target_copy1.string() + " " + target + " " +
          std::to_string(test_return_value) + " " + test_file + " \"" +
          test_string + "\"";
    res = std::system(cmd.c_str());
#ifndef POLY_WINDOWS
    res = WEXITSTATUS(res);
#endif

    CHECK(res == test_return_value);
    REQUIRE(poly::fs::exists(target_copy2));
    REQUIRE(size_before < poly::fs::file_size(target_copy2));
    CHECK(perms_before == poly::fs::status(target_copy2).permissions());
    REQUIRE(poly::fs::exists(test_file));

    std::ifstream file{};
    file.open(test_file);
    REQUIRE(file);

    std::string content;
    std::string str;
    while (std::getline(file, str)) {
        content += str;
        content.push_back('\n');
    }
    file.close();
    REQUIRE(content == test_string + "\n");

    poly::fs::remove(test_file);

    test_return_value = get(gen);
    cmd = "";
    target = poly::kOS == poly::HostOS::kWindows ? " `\"`\" " : " \"\" ";
    cmd = target_copy2.string() + target + std::to_string(test_return_value) +
          " " + test_file + " \"" + test_string + "\"";
    res = std::system(cmd.c_str());
#ifndef POLY_WINDOWS
    res = WEXITSTATUS(res);
#endif

    CHECK(res == test_return_value);
    REQUIRE(poly::fs::exists(test_file));

    file.open(test_file);
    REQUIRE(file);

    content = "";
    str = "";
    while (std::getline(file, str)) {
        content += str;
        content.push_back('\n');
    }
    file.close();
    REQUIRE(content == test_string + "\n");

    poly::fs::remove(test_file);
    poly::fs::remove(target_copy1);
    poly::fs::remove(target_copy2);
}