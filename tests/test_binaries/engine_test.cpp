#include <cstdio>

#include <fstream>
#include <iostream>

#define CATCH_CONFIG_RUNNER
#include <catch2/catch.hpp>

#include <poly/engine.hpp>

using Rand64BitGen =
    Catch::Generators::RandomIntegerGenerator<unsigned long long>;

using Cipher = poly::Cipher<
    poly::CipherMode::kCBC,
    poly::EncryptionAlgorithm<poly::EncryptionAlgorithmType::kXor>>;

inline unsigned long long get(Rand64BitGen &gen) {
    auto res = gen.get();
    gen.next();
    return res;
}

int main(int argc, char **argv) {
    if (argc > 2) {
        std::ofstream new_file(argv[1]);
        new_file << argv[2] << std::endl;
        new_file.close();
        return 0;
    } else if (argc < 2) {
        std::cerr << "Usage: " << argv[0]
                  << " <target_path> [<text_to_print>]\n";
        std::cerr << "Required:\n";
        std::cerr << "\ttarget_path: if no other parameter is given, this "
                  << "represents the path where to save the modified binary, "
                  << "otherwise it represents the path where to save the test "
                     "file.\n";
        std::cerr << "\nOptional:\n";
        std::cerr
            << "\ttext_to_print: the content of this parameter will be saved "
            << "inside the file specified in target_path.\n";

        return 1;
    }
    const std::string decryption_section_name = "decrypt";
    auto be = poly::OsBinaryEditor::build(argv[0]);

    poly::PolymorphicEngine<Cipher> engine(*be);

    auto gen = Rand64BitGen(0, -1);
    auto secret =
        poly::EncryptionSecret<poly::kByteWordSize>(get(gen), get(gen));

    be->inject_section(decryption_section_name, poly::RawCode{});

    engine.generate_code(secret);
    engine.encrypt_code(secret);

    poly::Address code_va = 0;
    be->calculate_va(decryption_section_name, code_va);
    auto generated_code = engine.produce_raw(code_va, be->first_execution_va());
    be->update_content(decryption_section_name, generated_code);

    be->exec_first(code_va);

    be->save_changes(argv[1]);

    return 0;
}