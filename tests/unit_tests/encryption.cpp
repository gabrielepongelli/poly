#include <catch2/catch.hpp>

#include <string>

#include <asmjit/asmjit.h>

#include <engine/encryption.hpp>
#include <engine/host_properties.hpp>

using Rand64BitGen =
    Catch::Generators::RandomIntegerGenerator<unsigned long long>;

inline unsigned long long get(Rand64BitGen &gen) {
    auto res = gen.get();
    gen.next();
    return res;
}

std::string gen_random_string(const int len, Rand64BitGen &gen) {
    constexpr char alphanum[] =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    constexpr auto n_chars = sizeof(alphanum) - 1;

    std::string tmp_s;
    tmp_s.reserve(len);

    for (int i = 0; i < len; i++) {
        tmp_s += alphanum[get(gen) % n_chars];
    }

    return tmp_s;
}

TEST_CASE("Encrypt and decrypt data", "[unit][encryption]") {
    auto gen = Rand64BitGen(0, -1);

    using MyCipher = poly::Cipher<
        poly::CipherMode::kCBC,
        poly::EncryptionAlgorithm<poly::EncryptionAlgorithmType::kXor>>;

    auto secret =
        poly::EncryptionSecret<poly::kByteWordSize>(get(gen), get(gen));

    SECTION("Encryption and decryption of aligned data") {
        auto size = (get(gen) % 255) * poly::kByteWordSize;
        auto data_to_encrypt = gen_random_string(size, gen);
        auto data_copy = data_to_encrypt;
        std::uint8_t *ptr_to_encrypt =
            reinterpret_cast<std::uint8_t *>(&data_to_encrypt[0]);

        poly::RawCode raw(ptr_to_encrypt, size);
        auto res = MyCipher::encrypt<>(raw, secret);

        SECTION("No error occurred and data modified") {
            REQUIRE(res == poly::Error::kNone);
            REQUIRE(data_to_encrypt != data_copy);
        }

        SECTION("Correct encryption and decryption procedures") {
            asmjit::FileLogger logger(stdout);
            asmjit::JitRuntime rt;
            asmjit::CodeHolder code;
            code.init(rt.environment());
            code.setLogger(&logger);
            asmjit::x86::Compiler cc(&code);

            auto *func_node =
                cc.addFunc(asmjit::FuncSignatureT<void, void *>());

            auto arg = cc.newUInt64();
            func_node->setArg(0, arg);

            auto exit_label = cc.newLabel();

            res = MyCipher::assemble_decryption<>(secret, cc, arg, size,
                                                  exit_label);

            REQUIRE(res == poly::Error::kNone);

            cc.bind(exit_label);
            cc.ret();
            cc.endFunc();
            cc.finalize();

            typedef void (*Decrypt)(void *);

            Decrypt decr;
            asmjit::Error err = rt.add(&decr, &code);

            REQUIRE(err == asmjit::kErrorOk);

            decr(ptr_to_encrypt);
            rt.release(decr);

            REQUIRE(data_to_encrypt == data_copy);
        }
    }

    SECTION("Encryption and decryption of not-aligned data") {
        auto size = (get(gen) % 255);
        while (size % poly::kByteWordSize == 0) {
            size = (get(gen) % 255);
        }

        auto data_to_encrypt = gen_random_string(size, gen);
        auto data_copy = data_to_encrypt;
        std::uint8_t *ptr_to_encrypt =
            reinterpret_cast<std::uint8_t *>(&data_to_encrypt[0]);

        poly::RawCode raw(ptr_to_encrypt, size);
        auto res = MyCipher::encrypt<>(raw, secret);

        SECTION("Encryption error raised") {
            REQUIRE(res == poly::Error::kNotAligned);
        }

        SECTION("Decryption error raised") {
            asmjit::JitRuntime rt;
            asmjit::CodeHolder code;
            code.init(rt.environment());
            asmjit::x86::Compiler cc(&code);

            auto *func_node =
                cc.addFunc(asmjit::FuncSignatureT<void, void *>());

            auto arg = cc.newUInt64();
            func_node->setArg(0, arg);

            auto exit_label = cc.newLabel();

            res = MyCipher::assemble_decryption<>(
                secret, cc, arg, data_to_encrypt.size(), exit_label);

            REQUIRE(res == poly::Error::kNotAligned);
        }
    }
}