#include <catch2/catch.hpp>

#include <cstdlib>

#include <fstream>
#include <iostream>
#include <string>

#include <LIEF/LIEF.hpp>
#include <boost/filesystem.hpp>

#include <engine/engine.hpp>

TEST_CASE("Code encryption on the fly", "[integration][engine]") {
    const std::string hello_world_bin =
        poly::kOS == poly::HostOS::kWindows ? "engine_test.exe" : "engine_test";
    const std::string result_bin =
        poly::kOS == poly::HostOS::kWindows ? "result.exe" : "result";
    const std::string test_file = "test.txt";

    std::string cmd = "";
    cmd = "./" + hello_world_bin + " " + result_bin;
    if (poly::kOS == poly::HostOS::kWindows) {
        cmd = cmd.replace(1, 1, "\\");
    }
    auto res = std::system(cmd.c_str());
#ifndef POLY_WINDOWS
    res = WEXITSTATUS(res);
#endif
    REQUIRE(res == 0);

    REQUIRE(boost::filesystem::exists(result_bin));

    boost::filesystem::permissions(result_bin,
                                   boost::filesystem::perms::owner_exe |
                                       boost::filesystem::perms::add_perms);

    const std::string test_string = "Hello, world!";
    cmd = "";
    cmd = "./" + hello_world_bin + " " + test_file + " \"" + test_string + "\"";
    if (poly::kOS == poly::HostOS::kWindows) {
        cmd = cmd.replace(1, 1, "\\");
    }
    res = std::system(cmd.c_str());
#ifndef POLY_WINDOWS
    res = WEXITSTATUS(res);
#endif
    REQUIRE(res == 0);

    REQUIRE(boost::filesystem::exists(test_file));

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

    boost::filesystem::remove(test_file);
    boost::filesystem::remove(result_bin);
}