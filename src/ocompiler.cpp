#include "poly/ocompiler.hpp"

#include <cstdint>

#include <algorithm>
#include <functional>
#include <vector>

#include <asmjit/asmjit.h>

#include "poly/enums.hpp"
#include "poly/utils.hpp"

namespace poly {

    namespace impl {

        Operand Assembler<NotOperation>::serialize(Compiler &c,
                                                   Operand op) noexcept {
            if (op.op.isMem()) {
                c.not_(op.mem);
                return op;
            } else if (op.op.isReg()) {
                c.not_(op.reg);
                return op;
            }

            return {};
        }

        Mutation *NotOperation::generate_new_mutation() noexcept {
            switch (get_casual_mutation_type({MutationType::kNotSimple})) {
            case MutationType::kNotSimple:
                return new RealMutation<MutationType::kNotSimple>();
            default:
                return nullptr;
            }
        }

        Operand
        Assembler<AndOperation>::serialize(Compiler &c,
                                           span<Operand, 2> operands) noexcept {
            if (std::all_of(operands.begin(), operands.end(),
                            [](auto &op) { return op.op.isMem(); })) {
                return {};
            }

            for (auto i = 0; i < operands.size(); i++) {
                if (operands[0].op.isMem() && operands[1].op.isReg()) {
                    c.and_(operands[0].mem, operands[1].reg);
                    return operands[0];
                } else if (operands[0].op.isMem() && operands[1].op.isImm()) {
                    c.and_(operands[0].mem, operands[1].imm);
                    return operands[0];
                } else if (operands[0].op.isReg() && operands[1].op.isReg()) {
                    c.and_(operands[0].reg, operands[1].reg);
                    return operands[0];
                } else if (operands[0].op.isReg() && operands[1].op.isMem()) {
                    c.and_(operands[0].reg, operands[1].mem);
                    return operands[0];
                } else if (operands[0].op.isReg() && operands[1].op.isImm()) {
                    c.and_(operands[0].reg, operands[1].imm);
                    return operands[0];
                }
                std::rotate(operands.begin(), operands.begin() + 1,
                            operands.end());
            }

            return {};
        }

        Mutation *AndOperation::generate_new_mutation() noexcept {
            switch (get_casual_mutation_type({MutationType::kAndSimple})) {
            case MutationType::kAndSimple:
                return new RealMutation<MutationType::kAndSimple>();
            default:
                return nullptr;
            }
        }

        Operand
        Assembler<OrOperation>::serialize(Compiler &c,
                                          span<Operand, 2> operands) noexcept {
            if (std::all_of(operands.begin(), operands.end(),
                            [](auto &op) { return op.op.isMem(); })) {
                return {};
            }

            for (auto i = 0; i < operands.size(); i++) {
                if (operands[0].op.isMem() && operands[1].op.isReg()) {
                    c.or_(operands[0].mem, operands[1].reg);
                    return operands[0];
                } else if (operands[0].op.isMem() && operands[1].op.isImm()) {
                    c.or_(operands[0].mem, operands[1].imm);
                    return operands[0];
                } else if (operands[0].op.isReg() && operands[1].op.isReg()) {
                    c.or_(operands[0].reg, operands[1].reg);
                    return operands[0];
                } else if (operands[0].op.isReg() && operands[1].op.isMem()) {
                    c.or_(operands[0].reg, operands[1].mem);
                    return operands[0];
                } else if (operands[0].op.isReg() && operands[1].op.isImm()) {
                    c.or_(operands[0].reg, operands[1].imm);
                    return operands[0];
                }
                std::rotate(operands.begin(), operands.begin() + 1,
                            operands.end());
            }

            return {};
        }

        Mutation *OrOperation::generate_new_mutation() noexcept {
            switch (get_casual_mutation_type(
                {MutationType::kOrSimple, MutationType::kOrRecursive})) {
            case MutationType::kOrSimple:
                return new RealMutation<MutationType::kOrSimple>();
            case MutationType::kOrRecursive:
                return new RealMutation<MutationType::kOrRecursive>();
            default:
                return nullptr;
            }
        }

        Operand
        Assembler<XorOperation>::serialize(Compiler &c,
                                           span<Operand, 2> operands) noexcept {
            if (std::all_of(operands.begin(), operands.end(),
                            [](auto &op) { return op.op.isMem(); })) {
                return {};
            }

            for (auto i = 0; i < operands.size(); i++) {
                if (operands[0].op.isMem() && operands[1].op.isReg()) {
                    c.xor_(operands[0].mem, operands[1].reg);
                    return operands[0];
                } else if (operands[0].op.isMem() && operands[1].op.isImm()) {
                    c.xor_(operands[0].mem, operands[1].imm);
                    return operands[0];
                } else if (operands[0].op.isReg() && operands[1].op.isReg()) {
                    c.xor_(operands[0].reg, operands[1].reg);
                    return operands[0];
                } else if (operands[0].op.isReg() && operands[1].op.isMem()) {
                    c.xor_(operands[0].reg, operands[1].mem);
                    return operands[0];
                } else if (operands[0].op.isReg() && operands[1].op.isImm()) {
                    c.xor_(operands[0].reg, operands[1].imm);
                    return operands[0];
                }
                std::rotate(operands.begin(), operands.begin() + 1,
                            operands.end());
            }

            return {};
        }

        Mutation *XorOperation::generate_new_mutation() noexcept {
            switch (get_casual_mutation_type(
                {MutationType::kXorSimple, MutationType::kXorRecursive})) {
            case MutationType::kXorSimple:
                return new RealMutation<MutationType::kXorSimple>();
            case MutationType::kXorRecursive:
                return new RealMutation<MutationType::kXorRecursive>();
            default:
                return nullptr;
            }
        }

        Operand
        Assembler<SumOperation>::serialize(Compiler &c,
                                           span<Operand, 2> operands) noexcept {
            if (std::all_of(operands.begin(), operands.end(),
                            [](auto &op) { return op.op.isMem(); })) {
                return {};
            }

            for (auto i = 0; i < operands.size(); i++) {
                if (operands[0].op.isMem() && operands[1].op.isReg()) {
                    c.add(operands[0].mem, operands[1].reg);
                    return operands[0];
                } else if (operands[0].op.isMem() && operands[1].op.isImm()) {
                    c.add(operands[0].mem, operands[1].imm);
                    return operands[0];
                } else if (operands[0].op.isReg() && operands[1].op.isReg()) {
                    c.add(operands[0].reg, operands[1].reg);
                    return operands[0];
                } else if (operands[0].op.isReg() && operands[1].op.isMem()) {
                    c.add(operands[0].reg, operands[1].mem);
                    return operands[0];

                } else if (operands[0].op.isReg() && operands[1].op.isImm()) {
                    c.add(operands[0].reg, operands[1].imm);
                    return operands[0];
                }
                std::rotate(operands.begin(), operands.begin() + 1,
                            operands.end());
            }

            return {};
        }

        Mutation *SumOperation::generate_new_mutation() noexcept {
            switch (get_casual_mutation_type(
                {MutationType::kSumSimple, MutationType::kSumRecursive})) {
            case MutationType::kSumSimple:
                return new RealMutation<MutationType::kSumSimple>();
            case MutationType::kSumRecursive:
                return new RealMutation<MutationType::kSumRecursive>();
            default:
                return nullptr;
            }
        }

        Operand Assembler<SubtractOperation>::serialize(
            Compiler &c, span<Operand, 2> operands) noexcept {
            if (std::all_of(operands.begin(), operands.end(),
                            [](auto &op) { return op.op.isMem(); })) {
                return {};
            }

            if (operands[0].op.isMem() && operands[1].op.isReg()) {
                c.sub(operands[0].mem, operands[1].reg);
                return operands[0];
            } else if (operands[0].op.isMem() && operands[1].op.isImm()) {
                c.sub(operands[0].mem, operands[1].imm);
                return operands[0];
            } else if (operands[0].op.isReg() && operands[1].op.isReg()) {
                c.sub(operands[0].reg, operands[1].reg);
                return operands[0];
            } else if (operands[0].op.isReg() && operands[1].op.isMem()) {
                c.sub(operands[0].reg, operands[1].mem);
                return operands[0];
            } else if (operands[0].op.isReg() && operands[1].op.isImm()) {
                c.sub(operands[0].reg, operands[1].imm);
                return operands[0];
            }

            return {};
        }

        Mutation *SubtractOperation::generate_new_mutation() noexcept {
            switch (
                get_casual_mutation_type({MutationType::kSubtractSimple,
                                          MutationType::kSubtractRecursive})) {
            case MutationType::kSubtractSimple:
                return new RealMutation<MutationType::kSubtractSimple>();
            case MutationType::kSubtractRecursive:
                return new RealMutation<MutationType::kSubtractRecursive>();
            default:
                return nullptr;
            }
        }

        Operand Assembler<MultiplyOperation>::serialize(
            Compiler &c, span<Operand, 2> operands) noexcept {
            if (std::none_of(operands.begin(), operands.end(), [](auto &op) {
                    return op.op.isImm() && (op.imm.value() % 2 == 0);
                })) {
                return {};
            }

            std::iter_swap(std::find_if(operands.begin(), operands.end(),
                                        [](auto &op) {
                                            return op.op.isImm() &&
                                                   (op.imm.value() % 2 == 0);
                                        }),
                           operands.rbegin());

            if (operands[0].op.isReg()) {
                c.sal(operands[0].reg,
                      asmjit::Imm(operands[1].imm.value() / 2));
                return operands[0];
            } else if (operands[0].op.isMem()) {
                c.sub(operands[0].mem,
                      asmjit::Imm(operands[1].imm.value() / 2));
                return operands[0];
            }

            return {};
        }

        Mutation *MultiplyOperation::generate_new_mutation() noexcept {
            switch (get_casual_mutation_type({MutationType::kMultiplySimple})) {
            case MutationType::kMultiplySimple:
                return new RealMutation<MutationType::kMultiplySimple>();
            default:
                return nullptr;
            }
        }

        Operand Assembler<TermNode>::assemble(TermNode &node,
                                              Compiler &c) noexcept {
            auto &op = node.data();

            if (op.op.isImm()) {
                return {op};
            }

            if (op.op.isReg()) {
                auto res = c.newGp(asmjit::x86::Gp::typeIdOf(op.reg.type()));
                c.mov(res, op.reg);
                return {res};
            }

            if (op.op.isMem()) {
                return {op};
            }

            return {};
        }

        Operand Assembler<OperationNode>::assemble(OperationNode &root,
                                                   Compiler &c) {
            std::stack<Operand> return_values;
            auto fn = [&c, &return_values](OperationNode &node) {
                if (node.left() != nullptr && node.left()->is_leaf()) {
                    return_values.push(Assembler<TermNode>::assemble(
                        *node.left()->as<TermNode>(), c));
                }

                if (node.right() != nullptr && node.right()->is_leaf()) {
                    return_values.push(Assembler<TermNode>::assemble(
                        *node.right()->as<TermNode>(), c));
                }

                std::vector<Operand> args(node.data()->arity());

                std::for_each(args.rbegin(), args.rend(),
                              [&return_values](auto &arg) {
                                  arg.op = return_values.top().op;
                                  return_values.pop();
                              });

                return_values.push(node.data()->assemble(c, args));
            };

            OperationNode::transform_tree(&root, fn);
            return return_values.top();
        }

        OperationNode::OperationNode(Operation *op) noexcept
            : SpecializedTreeNode<Operation *>{op} {}

        void OperationNode::transform_tree(OperationNode *root,
                                           ProcessFunc process) {
            std::function<void(TreeNode &)> fn = [process](TreeNode &node) {
                if (!node.is_leaf()) {
                    process(*node.as<OperationNode>());
                }
            };

            TreeNode::post_order(root, fn);
        }

        template <>
        void RealMutation<MutationType::kOrRecursive>::mutate(
            OperationNode &node) noexcept {
            auto *xor_node = OperationNode::build(new XorOperation);
            auto *and_node = OperationNode::build(new AndOperation);

            xor_node->left(node.left());
            xor_node->left()->parent(xor_node);
            xor_node->right(node.right());
            xor_node->right()->parent(xor_node);

            and_node->left(node.left()->copy_tree());
            and_node->left()->parent(and_node);
            and_node->right(node.right()->copy_tree());
            and_node->right()->parent(and_node);

            node.left(xor_node);
            node.left()->parent(&node);
            node.right(and_node);
            node.right()->parent(&node);
            node.change_operation(new SumOperation);
        }

        template <>
        void RealMutation<MutationType::kXorRecursive>::mutate(
            OperationNode &node) noexcept {
            auto *sum_node = OperationNode::build(new SumOperation);
            auto *multiply_node = OperationNode::build(new MultiplyOperation);
            auto *and_node = OperationNode::build(new AndOperation);

            sum_node->left(node.left());
            sum_node->left()->parent(sum_node);
            sum_node->right(node.right());
            sum_node->right()->parent(sum_node);

            multiply_node->left(TermNode::build(asmjit::Imm(2)));
            multiply_node->left()->parent(multiply_node);
            multiply_node->right(and_node);
            multiply_node->right()->parent(multiply_node);

            and_node->left(node.left()->copy_tree());
            and_node->left()->parent(and_node);
            and_node->right(node.right()->copy_tree());
            and_node->right()->parent(and_node);

            node.left(sum_node);
            node.left()->parent(&node);
            node.right(multiply_node);
            node.right()->parent(&node);
            node.change_operation(new SubtractOperation);
        }

        template <>
        void RealMutation<MutationType::kSumRecursive>::mutate(
            OperationNode &node) noexcept {
            auto *xor_node = OperationNode::build(new XorOperation);
            auto *multiply_node = OperationNode::build(new MultiplyOperation);
            auto *and_node = OperationNode::build(new AndOperation);

            xor_node->left(node.left());
            xor_node->left()->parent(xor_node);
            xor_node->right(node.right());
            xor_node->right()->parent(xor_node);

            multiply_node->left(TermNode::build(asmjit::Imm(2)));
            multiply_node->left()->parent(multiply_node);
            multiply_node->right(and_node);
            multiply_node->right()->parent(multiply_node);

            and_node->left(node.left()->copy_tree());
            and_node->left()->parent(and_node);
            and_node->right(node.right()->copy_tree());
            and_node->right()->parent(and_node);

            node.left(xor_node);
            node.left()->parent(&node);
            node.right(multiply_node);
            node.right()->parent(&node);
        }

        template <>
        void RealMutation<MutationType::kSubtractRecursive>::mutate(
            OperationNode &node) noexcept {
            auto *xor_node = OperationNode::build(new XorOperation);
            auto *multiply_node = OperationNode::build(new MultiplyOperation);
            auto *and_node = OperationNode::build(new AndOperation);
            auto *not_node = OperationNode::build(new NotOperation);

            xor_node->left(node.left());
            xor_node->left()->parent(xor_node);
            xor_node->right(node.right());
            xor_node->right()->parent(xor_node);

            multiply_node->left(TermNode::build(asmjit::Imm(2)));
            multiply_node->left()->parent(multiply_node);
            multiply_node->right(and_node);
            multiply_node->right()->parent(multiply_node);

            and_node->left(not_node);
            and_node->left()->parent(and_node);
            and_node->right(node.right()->copy_tree());
            and_node->right()->parent(and_node);

            not_node->right(node.left()->copy_tree());
            not_node->right()->parent(not_node);

            node.left(xor_node);
            node.left()->parent(&node);
            node.right(multiply_node);
            node.right()->parent(&node);
        }

        TermNode::TermNode(Operand &o) noexcept
            : SpecializedTreeNode<Operand>{nullptr, nullptr, nullptr, o} {}

        TermNode::TermNode(const Operand &o) noexcept
            : SpecializedTreeNode<Operand>{nullptr, nullptr, nullptr, o} {}

        void Obfuscator::expand(asmjit::Operand a, asmjit::Operand b,
                                Operation *op, Compiler &c) noexcept {
            if (op == nullptr) {
                return;
            }

            OperationNode *root = OperationNode::build(op);
            if (!a.isNone()) {
                root->left(TermNode::build(a));
                root->left()->parent(root);
            }
            if (!b.isNone()) {
                root->right(TermNode::build(b));
                root->right()->parent(root);
            }
            auto limit = generate_random();

            OperationNode::ProcessFunc fn = [&limit](OperationNode &node) {
                if (limit > 0) {
                    limit--;
                    Mutation *m = node.data()->generate_new_mutation();
                    m->mutate(node);
                }
            };

            while (limit > 0) {
                OperationNode::transform_tree(root, fn);
            }

            OperationNode::assemble_tree(root, c);
        }

        FuncObfPass::FuncObfPass() noexcept : asmjit::Pass{"FuncObfPass"} {}

        asmjit::Error FuncObfPass::run(asmjit::Zone *zone,
                                       asmjit::Logger *logger) noexcept {
            asmjit::BaseNode *node = this->_cb->firstNode();
            asmjit::BaseNode *succ = node->next();
            asmjit::InstNode *inst = nullptr;

            while (node != this->_cb->lastNode()) {
                if (node->isInst()) {
                    this->_cb->setCursor(node);
                    inst = node->template as<asmjit::InstNode>();

                    switch (inst->id()) {
                    case asmjit::x86::Inst::kIdNot:
                        Obfuscator::not_(inst->op(0),
                                         static_cast<Compiler &>(*this->_cb));
                        break;
                    case asmjit::x86::Inst::kIdAnd:
                        Obfuscator::and_(inst->op(0), inst->op(1),
                                         static_cast<Compiler &>(*this->_cb));
                        break;
                    case asmjit::x86::Inst::kIdOr:
                        Obfuscator::or_(inst->op(0), inst->op(1),
                                        static_cast<Compiler &>(*this->_cb));
                        break;
                    case asmjit::x86::Inst::kIdXor:
                        Obfuscator::xor_(inst->op(0), inst->op(1),
                                         static_cast<Compiler &>(*this->_cb));
                        break;
                    case asmjit::x86::Inst::kIdAdd:
                        Obfuscator::sum(inst->op(0), inst->op(1),
                                        static_cast<Compiler &>(*this->_cb));
                        break;
                    case asmjit::x86::Inst::kIdSub:
                        Obfuscator::subtract(
                            inst->op(0), inst->op(1),
                            static_cast<Compiler &>(*this->_cb));
                        break;
                    default:
                        node = nullptr;
                        break;
                    }

                    if (node != nullptr) {
                        asmjit::BaseNode *last_inst_generated = succ->prev();
                        while (!last_inst_generated->isInst()) {
                            last_inst_generated = last_inst_generated->prev();
                        }

                        if (last_inst_generated != node &&
                            inst->op(0) !=
                                last_inst_generated->as<asmjit::InstNode>()->op(
                                    0)) {
                            auto res = static_cast<Compiler *>(this->_cb)->mov(
                                inst->op(0).as<Register>(),
                                last_inst_generated->as<asmjit::InstNode>()
                                    ->op(0)
                                    .as<Register>());

                            if (res != asmjit::kErrorOk) {
                                return res;
                            }
                        }

                        this->_cb->removeNode(node);
                    }
                }

                node = succ;
                succ = succ->next();
            }

            this->_cb->setCursor(this->_cb->lastNode());
            return asmjit::kErrorOk;
        }

        NopPass::NopPass() noexcept : asmjit::Pass{"NopPass"} {}

        asmjit::Error NopPass::run(asmjit::Zone *zone,
                                   asmjit::Logger *logger) noexcept {
            asmjit::BaseNode *node = this->_cb->firstNode();

            while (node != this->_cb->lastNode()) {
                bool generate_nop = (RandomGenerator::get_generator()
                                         .get_random<unsigned short>() %
                                     10) == 0;

                node = node->next();

                if (generate_nop) {
                    asmjit::Error err;

                    this->_cb->setCursor(node->prev());
                    if ((err = static_cast<Compiler &>(*this->_cb).nop()) !=
                        asmjit::kErrorOk) {
                        return err;
                    }
                }
            }

            this->_cb->setCursor(this->_cb->lastNode());
            return asmjit::kErrorOk;
        }

    } // namespace impl

    OCompiler::OCompiler(asmjit::CodeHolder *code) noexcept : Compiler{} {
        if (code) {
            code->attach(this);
        }
    }

    asmjit::Error OCompiler::onAttach(asmjit::CodeHolder *code) noexcept {
        auto error = Compiler::onAttach(code);

        if (error != asmjit::kErrorOk) {
            onDetach(code);
            return error;
        }

        error = addPassT<impl::FuncObfPass>();

        if (error != asmjit::kErrorOk) {
            onDetach(code);
            return error;
        }

        if (_passes.size() > 1) {
            // rotate all the passes that will be executed in order to preserve
            // the original order, but positioning FuncObfPass in the first
            // position
            std::rotate(_passes.rbegin(), _passes.rbegin() + 1, _passes.rend());
        }

        error = addPassT<impl::NopPass>();

        if (error != asmjit::kErrorOk) {
            onDetach(code);
            return error;
        }

        return asmjit::kErrorOk;
    }

} // namespace poly