#include "engine/code_container.hpp"

#include <cstdint>

#include <algorithm>
#include <unordered_set>
#include <vector>

#include <asmjit/asmjit.h>

#include "engine/enums.hpp"
#include "engine/utils.hpp"

namespace poly {

    namespace impl {

        inline std::size_t
        OperandHash::operator()(asmjit::Operand_ const &op) const noexcept {
            return op.signature().bits();
        }

    } // namespace impl

    CodeContainer::StackPosition::StackPosition(const asmjit::x86::Mem &mem)
        : memory_block{mem}, releasable{false} {}

    inline bool CodeContainer::StackPosition::operator==(
        const CodeContainer::StackPosition &oth) const {
        return this->memory_block == oth.memory_block &&
               this->releasable == oth.releasable;
    }

    inline std::unordered_set<asmjit::x86::Gp, impl::OperandHash>
    CodeContainer::get_all_registers() {
        return {builder_.zax(),
                builder_.zbx(),
                builder_.zcx(),
                builder_.zdx(),
                builder_.zbp(),
                builder_.zsp(),
                builder_.zsi(),
                builder_.zdi(),
                builder_.gpz(asmjit::x86::Gp::kIdR8),
                builder_.gpz(asmjit::x86::Gp::kIdR9),
                builder_.gpz(asmjit::x86::Gp::kIdR10),
                builder_.gpz(asmjit::x86::Gp::kIdR11),
                builder_.gpz(asmjit::x86::Gp::kIdR12),
                builder_.gpz(asmjit::x86::Gp::kIdR13),
                builder_.gpz(asmjit::x86::Gp::kIdR14),
                builder_.gpz(asmjit::x86::Gp::kIdR15)};
    }

    CodeContainer::CodeContainer()
        : code_holder_{}, builder_{}, free_registers_{get_all_registers()},
          used_registers_{}, untouchable_registers_{}, used_stack_{},
          empty_operand_{} {
        code_holder_.init(asmjit::Environment::host());
        code_holder_.attach(&builder_);

        StackPosition first(asmjit::x86::Mem(builder_.zsp(), 0));
        used_stack_.push_back(first);
    }

    inline asmjit::x86::Builder &CodeContainer::builder() { return builder_; }

    EditableCodeError CodeContainer::mark_as_free(const asmjit::Operand &op) {
        if (!op.isRegOrMem()) {
            return EditableCodeError::kInvalidOperand;
        }

        if (op.isPhysReg()) {
            auto reg = op.as<asmjit::x86::Gp>();

            if (untouchable_registers_.find(reg.r64()) !=
                untouchable_registers_.end()) {

                auto used_it = used_registers_.find(reg);
                if (used_it != used_registers_.end()) {
                    used_registers_.erase(used_it);
                }

                return EditableCodeError::kOperandIsUntouchable;
            }

            auto it = used_registers_.find(reg);
            used_registers_.erase(it);
            free_registers_.insert(reg.r64());

        } else {
            auto &mem = op.as<asmjit::x86::Mem>();

            auto it = std::find(used_stack_.rbegin(), used_stack_.rend(),
                                StackPosition{mem});

            // the memory wasn't in use
            if (it == used_stack_.rend()) {
                return EditableCodeError::kNone;
            }
            it->releasable = true;

            // release all the positions marked as releasable
            while (used_stack_.size() > 0 && used_stack_.back().releasable) {
                used_stack_.pop_back();
            }
        }

        return EditableCodeError::kNone;
    }

    EditableCodeError
    CodeContainer::mark_as_untouchable(const asmjit::Operand &op) {
        if (!op.isPhysReg()) {
            return EditableCodeError::kInvalidOperand;
        }

        auto reg = op.as<asmjit::x86::Gp>();

        auto it = free_registers_.find(reg.r64());
        if (it != free_registers_.end()) {
            free_registers_.erase(it);
        }

        untouchable_registers_.insert(reg.r64());

        return EditableCodeError::kNone;
    }

    const asmjit::Operand &
    CodeContainer::get_virtual_register(std::uint8_t size) {
        if (size == 0) {
            return empty_operand_;
        }

        if (free_registers_.size() > 0 && (size & (size - 1)) == 0 &&
            size <= impl::byte_word_size) {
            if (RandomGenerator::get_generator().get_random<bool>()) {
                auto &random_reg =
                    RandomGenerator::get_generator().random_from_it(
                        free_registers_, free_registers_.size());

                auto it = free_registers_.find(random_reg);
                if (it != free_registers_.end()) {
                    free_registers_.erase(it);
                }

                switch (size) {
                case 1:
                    return *used_registers_.insert(random_reg.r8()).first;
                case 2:
                    return *used_registers_.insert(random_reg.r16()).first;
                case 4:
                    return *used_registers_.insert(random_reg.r32()).first;
                default:
                    return *used_registers_.insert(random_reg.r64()).first;
                }
            }
        }

        StackPosition p(asmjit::x86::Mem(
            builder_.zsp(), used_stack_.back().memory_block.offset() - size));

        used_stack_.push_back(p);

        return used_stack_.back().memory_block;
    }

    RawCode CodeContainer::produce_raw(Address jump_to, Address section_va,
                                       std::uint32_t alignement) {
        builder_.jmp(jump_to);

        auto *text_section = code_holder_.textSection();

        text_section->setAlignment(alignement);
        builder_.finalize();
        code_holder_.flatten();
        code_holder_.resolveUnresolvedLinks();
        code_holder_.relocateToBase(section_va);

        RawCode res{text_section->data(),
                    text_section->data() + text_section->realSize()};
        return res;
    }

} // namespace poly
