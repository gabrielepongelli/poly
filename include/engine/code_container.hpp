#pragma once

#include <cstdint>

#include <unordered_set>
#include <vector>

#include <asmjit/asmjit.h>

#include "enums.hpp"
#include "host_properties.hpp"
#include "utils.hpp"

namespace poly {

    namespace impl {

        struct OperandHash {

            std::size_t operator()(asmjit::Operand_ const &op) const noexcept;
        };

    } // namespace impl

    using Compiler = asmjit::x86::Compiler;

    using Register = asmjit::x86::Gp;

    /**
     * ExecutableCode is an interface that defines a method to obtain the raw
     * code ready for being stored and used.
     */
    class ExecutableCode {
      public:
        virtual ~ExecutableCode() = default;

        /**
         * Obtain raw bytes that represent executable code.
         * @param jump_tp the virtual address of the location where the code
         * should jump after its execution.
         * @param section_va the virtual address of the section where the code
         * will be placed. It is used to resolve possible relative addresses.
         * @param alignement the alignement value of the final raw code. Default
         * to the host's word size.
         * @return the raw code ready for being allocated and executed.
         */
        virtual RawCode
        produce_raw(Address jump_to, Address section_va,
                    std::uint32_t alignement = kByteWordSize) = 0;
    };

    /**
     * EditableCode is an interface that defines some methods which can be used
     * to modify an abstract representation of the desired code.
     */
    class EditableCode {
      public:
        virtual ~EditableCode() = default;

        /**
         * Get a free virtual register ready to be used. Note: a virtual
         * register can be a real register, or a memory location on the stack.
         * @param size the required size in bytes. Default to the host's word
         * size.
         * @return the required operand. If size is 0, an operand of type kNone
         * will be returned.
         */
        virtual const asmjit::Operand &
        get_virtual_register(std::uint8_t size = kByteWordSize) = 0;

        /**
         * Mark the specified operand as free to be reused.
         * @param op operand to mark as free. Only register and memory operands
         * are accepted.
         * @return kNone if everything is ok. If op isn't an operand of the
         * right type, kInvalidOperand will be returned. If op has been marked
         * as untouchable, kOperandIsUntouchable will be returned.
         */
        virtual Error mark_as_free(const asmjit::Operand &op) = 0;

        /**
         * Get a compiler object ready to generate new instructions.
         */
        virtual Compiler &compiler() = 0;

        /**
         * Mark the specified operand as untouchable. An operand marked as
         * untouchable cannot be returned by the get_virtual_register method as
         * it will not be free. WARNING: once an operand is marked this way it
         * is not possible to unmark it.
         * @param op operand to mark as free. Only register operands are
         * accepted.
         * @return kNone if everything is ok. If op isn't an operand of the
         * right type, kInvalidOperand will be returned.
         */
        virtual Error mark_as_untouchable(const asmjit::Operand &op) = 0;
    };

    class CodeContainer : public ExecutableCode, public EditableCode {
      public:
        CodeContainer();
        ~CodeContainer() = default;

        RawCode produce_raw(Address jump_to, Address section_va,
                            std::uint32_t alignement = kByteWordSize);

        const asmjit::Operand &
        get_virtual_register(std::uint8_t size = kByteWordSize);

        Error mark_as_free(const asmjit::Operand &op);

        Compiler &compiler();

        Error mark_as_untouchable(const asmjit::Operand &op);

      private:
        struct StackPosition {
            asmjit::x86::Mem memory_block;
            bool releasable;

            StackPosition(const asmjit::x86::Mem &mem);

            bool operator==(const StackPosition &oth) const;
        };

        std::unordered_set<asmjit::x86::Gp, impl::OperandHash>
        get_all_registers();

        asmjit::CodeHolder code_holder_;
        Compiler compiler_;
        std::unordered_set<asmjit::x86::Gp, impl::OperandHash> free_registers_;
        std::unordered_set<asmjit::x86::Gp, impl::OperandHash> used_registers_;
        std::unordered_set<asmjit::x86::Gp, impl::OperandHash>
            untouchable_registers_;
        std::vector<StackPosition> used_stack_;
        const asmjit::Operand empty_operand_;
    };

} // namespace poly
