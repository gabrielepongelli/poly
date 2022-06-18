#include <catch2/catch.hpp>

#include <cstdlib>

#include <fstream>
#include <string>

#include <poly/filesystem.hpp>
#include <poly/host_properties.hpp>

TEST_CASE("Code encryption on the fly", "[integration][engine]") {
    const poly::fs::path test_bin{poly::kOS == poly::HostOS::kWindows
                                      ? "./engine_test.exe"
                                      : "./engine_test"};
    const poly::fs::path result_bin{
        poly::kOS == poly::HostOS::kWindows ? "./result.exe" : "./result"};
    const poly::fs::path test_file{"test.txt"};

    std::string cmd = "";
    cmd = test_bin.string() + " " + result_bin.string();
    auto res = std::system(cmd.c_str());
#ifndef POLY_WINDOWS
    res = WEXITSTATUS(res);
#endif
    REQUIRE(res == 0);

    REQUIRE(poly::fs::exists(result_bin));

    poly::fs::permissions(result_bin, poly::fs::perms::owner_exec,
                          poly::fs::perm_options::add);

    const std::string test_string = "Hello, world!";
    cmd = "";
    cmd = result_bin.string() + " " + test_file.string() + " \"" + test_string +
          "\"";
    res = std::system(cmd.c_str());
#ifndef POLY_WINDOWS
    res = WEXITSTATUS(res);
#endif
    REQUIRE(res == 0);

    REQUIRE(poly::fs::exists(test_file));

    std::ifstream file(test_file);
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
    poly::fs::remove(result_bin);
}