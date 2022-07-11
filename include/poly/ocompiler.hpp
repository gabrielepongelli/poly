#pragma once

#include <cstdint>

#include <algorithm>
#include <functional>
#include <memory>
#include <stack>
#include <string>
#include <vector>

#include <asmjit/asmjit.h>

#include "enums.hpp"
#include "utils.hpp"

namespace poly {

    namespace impl {

        /**
         * This type was created in order to facilitate the casting to
         * asmjit::Operand subtypes. Since one of the features of
         * asmjit::Operand is that all of its subclasses must not introduce new
         * members, this class represents a different interpretation of the same
         * data.
         */
        union Operand {
            asmjit::Operand op;
            asmjit::Imm imm;
            asmjit::x86::Mem mem;
            asmjit::x86::Gp reg;

            Operand(const asmjit::Operand &o) : op{o} {}
            Operand(const Operand &o) : op{o.op} {}
            Operand() : op{} {}

            inline Operand &operator=(const Operand &oth) {
                op = oth.op;
                return *this;
            }
        };

        /**
         * Class responsible of transforming its template type T into assembly
         * code. Must be specialized.
         */
        template <typename T>
        struct Assembler {};

        class Operation;
        class NotOperation;
        class AndOperation;
        class OrOperation;
        class XorOperation;
        class SumOperation;
        class SubtractOperation;
        class MultiplyOperation;
        class OperationNode;

        /**
         * Describe a mutation of an OperationNode which may change the
         * operations used without changing the overall result.
         */
        class Mutation {
          public:
            /**
             * Apply the mutation.
             * @param node node on which the mutation has to be applied.
             */
            virtual void mutate(OperationNode &node) noexcept = 0;
        };

        /**
         * Concrete base implementation of the Mutation interface.
         * Must be specialized.
         */
        template <MutationType Type>
        class RealMutation : public Mutation {
          public:
            inline void mutate(OperationNode &node) noexcept {};
        };

        /**
         * Assembler specialization for a generic operation.
         */
        template <>
        struct Assembler<Operation> {

            /**
             * Interface which must be implemented by the concrete operation in
             * order to be assembled.
             */
            struct Assemblable {

                /**
                 * @param c compiler used to assemble the operation.
                 * @param operands list of operands used by the operation.
                 * @return the operand where its result is stored.
                 */
                virtual Operand assemble(Compiler &c,
                                         std::vector<Operand> &operands) = 0;
            };
        };

        /**
         * Abstract class which defines all the method that a specific concrete
         * operation must provide. This object can be saved into OperationNode.
         */
        class Operation : public Assembler<Operation>::Assemblable {
          public:
            Operation() noexcept = default;
            virtual ~Operation() = default;

            /**
             * Generate a new mutation for this operation.
             * @return the new mutation to apply.
             */
            virtual Mutation *generate_new_mutation() noexcept = 0;

            /**
             * Create a copy of this operation.
             * @return the newly created copy.
             */
            virtual Operation *copy() const noexcept = 0;

            /**
             * @return the arity of this operation.
             */
            virtual std::size_t arity() const noexcept = 0;

          protected:
            /**
             * Casually choose a new mutation type to use.
             * @param types all the mutation types valid for this operation.
             * @return the mutation type chosen.
             */
            inline MutationType get_casual_mutation_type(
                const std::vector<MutationType> &types) noexcept {
                return RandomGenerator::get_generator()
                    .random_from<MutationType>(types);
            }
        };

        /**
         * Concrete implementation of the Assembler class which transform
         * NotOperations.
         */
        template <>
        struct Assembler<NotOperation> {

            /**
             * Transform this operation into assembly code.
             * @param c compiler used to generate the assembly code.
             * @param op operand passed to this operation.
             * @return the operand where the operation's result will be saved.
             */
            static Operand serialize(Compiler &c, Operand op) noexcept;
        };

        /**
         * Concrete operation which represents the "not" operation.
         */
        class NotOperation : public Operation {
          public:
            Mutation *generate_new_mutation() noexcept override;

            inline Operand
            assemble(Compiler &c,
                     std::vector<Operand> &operands) noexcept override {
                return Assembler<NotOperation>::serialize(c, operands.at(0));
            }

            inline Operation *copy() const noexcept override {
                return new NotOperation();
            }

            inline std::size_t arity() const noexcept override { return 1; }
        };

        /**
         * Concrete implementation of the Assembler class which transform
         * AndOperations.
         */
        template <>
        struct Assembler<AndOperation> {

            /**
             * Transform this operation into assembly code.
             * @param c compiler used to generate the assembly code.
             * @param operands operands passed to this operation.
             * @return the operand where the operation's result will be saved.
             */
            static Operand serialize(Compiler &c,
                                     span<Operand, 2> operands) noexcept;
        };

        /**
         * Concrete operation which represents the "and" operation.
         */
        class AndOperation : public Operation {
          public:
            Mutation *generate_new_mutation() noexcept override;

            inline Operand
            assemble(Compiler &c,
                     std::vector<Operand> &operands) noexcept override {
                return Assembler<AndOperation>::serialize(c,
                                                          {operands.data(), 2});
            }

            inline Operation *copy() const noexcept override {
                return new AndOperation();
            }

            inline std::size_t arity() const noexcept override { return 2; }
        };

        /**
         * Concrete implementation of the Assembler class which transform
         * OrOperations.
         */
        template <>
        struct Assembler<OrOperation> {

            /**
             * Transform this operation into assembly code.
             * @param c compiler used to generate the assembly code.
             * @param operands operands passed to this operation.
             * @return the operand where the operation's result will be saved.
             */
            static Operand serialize(Compiler &c,
                                     span<Operand, 2> operands) noexcept;
        };

        /**
         * Concrete operation which represents the "or" operation.
         */
        class OrOperation : public Operation {
          public:
            Mutation *generate_new_mutation() noexcept override;

            inline Operand
            assemble(Compiler &c,
                     std::vector<Operand> &operands) noexcept override {
                return Assembler<OrOperation>::serialize(c,
                                                         {operands.data(), 2});
            }

            inline Operation *copy() const noexcept override {
                return new OrOperation();
            }

            inline std::size_t arity() const noexcept override { return 2; }
        };

        /**
         * Concrete implementation of the Assembler class which transform
         * XorOperations.
         */
        template <>
        struct Assembler<XorOperation> {

            /**
             * Transform this operation into assembly code.
             * @param c compiler used to generate the assembly code.
             * @param operands operands passed to this operation.
             * @return the operand where the operation's result will be saved.
             */
            static Operand serialize(Compiler &c,
                                     span<Operand, 2> operands) noexcept;
        };

        /**
         * Concrete operation which represents the "xor" operation.
         */
        class XorOperation : public Operation {
          public:
            Mutation *generate_new_mutation() noexcept override;

            inline Operand
            assemble(Compiler &c,
                     std::vector<Operand> &operands) noexcept override {
                return Assembler<XorOperation>::serialize(c,
                                                          {operands.data(), 2});
            }

            inline Operation *copy() const noexcept override {
                return new XorOperation();
            }

            inline std::size_t arity() const noexcept override { return 2; }
        };

        /**
         * Concrete implementation of the Assembler class which transform
         * SumOperations.
         */
        template <>
        struct Assembler<SumOperation> {

            /**
             * Transform this operation into assembly code.
             * @param c compiler used to generate the assembly code.
             * @param operands operands passed to this operation.
             * @return the operand where the operation's result will be saved.
             */
            static Operand serialize(Compiler &c,
                                     span<Operand, 2> operands) noexcept;
        };

        /**
         * Concrete operation which represents the "sum" operation.
         */
        class SumOperation : public Operation {
          public:
            Mutation *generate_new_mutation() noexcept override;

            inline Operand
            assemble(Compiler &c,
                     std::vector<Operand> &operands) noexcept override {
                return Assembler<SumOperation>::serialize(c,
                                                          {operands.data(), 2});
            }

            inline Operation *copy() const noexcept override {
                return new SumOperation();
            }

            inline std::size_t arity() const noexcept override { return 2; }
        };

        /**
         * Concrete implementation of the Assembler class which transform
         * SubtractOperations.
         */
        template <>
        struct Assembler<SubtractOperation> {

            /**
             * Transform this operation into assembly code.
             * @param c compiler used to generate the assembly code.
             * @param operands operands passed to this operation.
             * @return the operand where the operation's result will be saved.
             */
            static Operand serialize(Compiler &c,
                                     span<Operand, 2> operands) noexcept;
        };

        /**
         * Concrete operation which represents the "subtraction" operation.
         */
        class SubtractOperation : public Operation {
          public:
            Mutation *generate_new_mutation() noexcept override;

            inline Operand
            assemble(Compiler &c,
                     std::vector<Operand> &operands) noexcept override {
                return Assembler<SubtractOperation>::serialize(
                    c, {operands.data(), 2});
            }

            inline Operation *copy() const noexcept override {
                return new SubtractOperation();
            }

            inline std::size_t arity() const noexcept override { return 2; }
        };

        /**
         * Concrete implementation of the Assembler class which transform
         * MultiplyOperations.
         */
        template <>
        struct Assembler<MultiplyOperation> {

            /**
             * Transform this operation into assembly code.
             * @param c compiler used to generate the assembly code.
             * @param operands operands passed to this operation.
             * @return the operand where the operation's result will be saved.
             */
            static Operand serialize(Compiler &c,
                                     span<Operand, 2> operands) noexcept;
        };

        /**
         * Concrete operation which represents the "multiplication" operation.
         */
        class MultiplyOperation : public Operation {
          public:
            Mutation *generate_new_mutation() noexcept override;

            inline Operand
            assemble(Compiler &c,
                     std::vector<Operand> &operands) noexcept override {
                return Assembler<MultiplyOperation>::serialize(
                    c, {operands.data(), 2});
            }

            inline Operation *copy() const noexcept override {
                return new MultiplyOperation();
            }

            inline std::size_t arity() const noexcept override { return 2; }
        };

        /**
         * A TermNode is a specialized tree node which contains an operand. It
         * can only be inserted as leaf in a tree.
         */
        class TermNode : public SpecializedTreeNode<Operand> {
          public:
            TermNode(Operand &o) noexcept;

            TermNode(const Operand &o) noexcept;

            inline TreeNode *left() const noexcept override { return nullptr; }

            inline TreeNode *left(TreeNode *new_left) noexcept override {
                return nullptr;
            }

            inline TreeNode *right() const noexcept override { return nullptr; }

            inline TreeNode *right(TreeNode *new_right) noexcept override {
                return nullptr;
            }

            inline bool is_leaf() const noexcept override { return true; }

            inline TreeNode *copy_tree() const noexcept override {
                Operand new_data(this->data_);
                return new TermNode(new_data);
            }

            static inline TermNode *build(Operand &op) noexcept {
                return new TermNode(op);
            }

            static inline TermNode *build(const Operand &op) noexcept {
                return new TermNode(op);
            }

          protected:
            inline TreeNode *copy_node() const noexcept override {
                return TermNode::build(this->data_);
            }
        };

        /**
         * Concrete implementation of the Assembler class which transform
         * TermNodes.
         */
        template <>
        struct Assembler<TermNode> {

            /**
             * Transform a TreeNode into assembly code.
             * @param node TermNode which has to be transformed.
             * @param c compiler used to generate the assembly code.
             * @return the operand represented by the transformed TermNode.
             */
            static Operand assemble(TermNode &node, Compiler &c) noexcept;
        };

        /**
         * Concrete implementation of the Assembler class which transform
         * OperationNodes.
         */
        template <>
        struct Assembler<OperationNode> {

            /**
             * Transform a tree of operations into assembly code.
             * @param root root of the tree which has to be transformed.
             * @param c compiler used to generate the assembly code.
             * @return the operand where the result of the tree will be saved.
             */
            static Operand assemble(OperationNode &root, Compiler &c);
        };

        /**
         * An OperationNode is a specialized tree node which contains an
         * operation. It must have at least one child.
         */
        class OperationNode : public SpecializedTreeNode<Operation *> {
          public:
            using ProcessFunc = std::function<void(OperationNode &node)>;

            OperationNode(Operation *op) noexcept;

            virtual inline ~OperationNode() { delete data_; }

            inline bool is_leaf() const noexcept override { return false; }

            /**
             * Change the operation represented by this node. NOTE: the old
             * operation will be destroied.
             * @param new_op the new operation represented by this node.
             */
            inline void change_operation(Operation *new_op) noexcept {
                delete data_;
                data_ = new_op;
            }

            static inline OperationNode *build(Operation *op) noexcept {
                return new OperationNode(op);
            }

            /**
             * Iterate over all the OperationNodes of a tree and process each of
             * them. The visit will be performed post-order.
             * @param root root of the tree to process.
             * @param process function used to process each OperationNode of the
             * tree. The node to process will be passed by argument to the
             * function.
             */
            static void transform_tree(OperationNode *root,
                                       ProcessFunc process);

            /**
             * Transform a tree of operations into assembly code.
             * @param root root of the tree which has to be transformed.
             * @param c compiler used to generate the assembly code.
             */
            inline static void assemble_tree(OperationNode *root, Compiler &c) {
                Assembler<OperationNode>::assemble(*root, c);
            }

          protected:
            inline TreeNode *copy_node() const noexcept override {
                Operation *new_data = data_->copy();
                return OperationNode::build(new_data);
            }
        };

        /**
         * Concrete implementation of the Mutation interface specialized on
         * MutationType::kOrRecursive mutations.
         */
        template <>
        void RealMutation<MutationType::kOrRecursive>::mutate(
            OperationNode &node) noexcept;

        /**
         * Concrete implementation of the Mutation interface specialized on
         * MutationType::kXorRecursive mutations.
         */
        template <>
        void RealMutation<MutationType::kXorRecursive>::mutate(
            OperationNode &node) noexcept;

        /**
         * Concrete implementation of the Mutation interface specialized on
         * MutationType::kSumRecursive mutations.
         */
        template <>
        void RealMutation<MutationType::kSumRecursive>::mutate(
            OperationNode &node) noexcept;

        /**
         * Concrete implementation of the Mutation interface specialized on
         * MutationType::kSubtractRecursive mutations.
         */
        template <>
        void RealMutation<MutationType::kSubtractRecursive>::mutate(
            OperationNode &node) noexcept;

        /**
         * Class which add the capability to perform obfuscated "not" operations
         * applied to a type T. The Derived class must implement the following
         * method:
         *      static void expand(
         *          T, asmjit::Operand, Operation *, Compiler &) noexcept
         */
        template <typename T, class Derived>
        class NegateCapability {
          public:
            /**
             * Perform the "not" operation on the operand specified.
             * @param a operand on which to apply the operation.
             * @param c compiler used to generate the assembly code.
             */
            static inline void not_(const T &a, Compiler &c) noexcept {
                Derived::expand(a, {}, new NotOperation{}, c);
            }
        };

        /**
         * Class which add the capability to perform obfuscated "and" operations
         * applied to a type T. The Derived class must implement the following
         * method:
         *      static void expand(
         *          T, asmjit::Operand, Operation *, Compiler &) noexcept
         */
        template <typename T, class Derived>
        class AndCapability {
          public:
            /**
             * Perform the "and" operation on the operands specified.
             * @param a left operand on which to apply the operation.
             * @param b right operand on which to apply the operation.
             * @param c compiler used to generate the assembly code.
             */
            static inline void and_(const T &a, const T &b,
                                    Compiler &c) noexcept {
                Derived::expand(a, b, new AndOperation{}, c);
            }
        };

        /**
         * Class which add the capability to perform obfuscated "or" operations
         * applied to a type T. The Derived class must implement the following
         * method:
         *      static void expand(
         *          T, asmjit::Operand, Operation *, Compiler &) noexcept
         */
        template <typename T, class Derived>
        class OrCapability {
          public:
            /**
             * Perform the "or" operation on the operands specified.
             * @param a left operand on which to apply the operation.
             * @param b right operand on which to apply the operation.
             * @param c compiler used to generate the assembly code.
             */
            static inline void or_(const T &a, const T &b,
                                   Compiler &c) noexcept {
                Derived::expand(a, b, new OrOperation{}, c);
            }
        };

        /**
         * Class which add the capability to perform obfuscated "xor" operations
         * applied to a type T. The Derived class must implement the following
         * method:
         *      static void expand(
         *          T, asmjit::Operand, Operation *, Compiler &) noexcept
         */
        template <typename T, class Derived>
        class XorCapability {
          public:
            /**
             * Perform the "xor" operation on the operands specified.
             * @param a left operand on which to apply the operation.
             * @param b right operand on which to apply the operation.
             * @param c compiler used to generate the assembly code.
             */
            static inline void xor_(const T &a, const T &b,
                                    Compiler &c) noexcept {
                Derived::expand(a, b, new XorOperation{}, c);
            }
        };

        /**
         * Class which add the capability to perform obfuscated "sum" operations
         * applied to a type T. The Derived class must implement the following
         * method:
         *      static void expand(
         *          T, asmjit::Operand, Operation *, Compiler &) noexcept
         */
        template <typename T, class Derived>
        class SumCapability {
          public:
            /**
             * Perform the "sum" operation on the operands specified.
             * @param a left operand on which to apply the operation.
             * @param b right operand on which to apply the operation.
             * @param c compiler used to generate the assembly code.
             */
            static inline void sum(const T &a, const T &b,
                                   Compiler &c) noexcept {
                Derived::expand(a, b, new SumOperation{}, c);
            }
        };

        /**
         * Class which add the capability to perform obfuscated "subtraction"
         * operations applied to a type T. The Derived class must implement the
         * following method:
         *      static void expand(
         *          T, asmjit::Operand, Operation *, Compiler &) noexcept
         */
        template <typename T, class Derived>
        class SubtractCapability {
          public:
            /**
             * Perform the "subtract" operation on the operands specified.
             * @param a left operand on which to apply the operation.
             * @param b right operand on which to apply the operation.
             * @param c compiler used to generate the assembly code.
             */
            static inline void subtract(const T &a, const T &b,
                                        Compiler &c) noexcept {
                Derived::expand(a, b, new SubtractOperation{}, c);
            }
        };

        /**
         * Class which add the capability to perform obfuscated "multiplication"
         * operations applied to a type T. The Derived class must implement the
         * following method:
         *      static void expand(
         *          T, asmjit::Operand, Operation *, Compiler &) noexcept
         */
        template <typename T, class Derived>
        class MultiplyCapability {
          public:
            /**
             * Perform the "multiply" operation on the operands specified.
             * @param a left operand on which to apply the operation.
             * @param b right operand on which to apply the operation.
             * @param c compiler used to generate the assembly code.
             */
            static inline void multiply(const T &a, const T &b,
                                        Compiler &c) noexcept {
                Derived::expand(a, b, new MultiplyOperation{}, c);
            }
        };

        /**
         * An Obfuscator is a class which can perform some assembly operations
         * obfuscating them without changing the overall result of the
         * operation.
         */
        class Obfuscator
            : public NegateCapability<asmjit::Operand, Obfuscator>,
              public AndCapability<asmjit::Operand, Obfuscator>,
              public OrCapability<asmjit::Operand, Obfuscator>,
              public XorCapability<asmjit::Operand, Obfuscator>,
              public SumCapability<asmjit::Operand, Obfuscator>,
              public SubtractCapability<asmjit::Operand, Obfuscator>,
              public MultiplyCapability<asmjit::Operand, Obfuscator> {
          public:
            /**
             * Expand the operation specified to a chain of other operations
             * with the same result of the original one.
             * @param a left operand of the operation to expand.
             * @param b right operand of the operation to expand.
             * @param op operation to expand. Must be a valid pointer.
             * @param c compiler used to generate the assembly code.
             */
            static void expand(asmjit::Operand a, asmjit::Operand b,
                               Operation *op, Compiler &c) noexcept;

          private:
            /**
             * @return a random number in [0, 255].
             */
            static inline std::uint8_t generate_random() noexcept {
                return static_cast<std::uint8_t>(
                    RandomGenerator::get_generator()
                        .get_random<unsigned short>() %
                    256);
            }
        };

        /**
         * Pass which scan the code generated by a compiler and obfuscate some
         * instructions.
         * This pass must be executed before the one which perform register
         * allocation because it uses virtual registers.
         */
        class FuncObfPass : public asmjit::Pass {
          public:
            FuncObfPass() noexcept;

            asmjit::Error run(asmjit::Zone *zone,
                              asmjit::Logger *logger) noexcept;
        };

        /**
         * Pass which scan the code and insert nop operations randomly.
         */
        class NopPass : public asmjit::Pass {
          public:
            NopPass() noexcept;

            asmjit::Error run(asmjit::Zone *zone,
                              asmjit::Logger *logger) noexcept;
        };

    } // namespace impl

    /**
     * This compiler which can be used as a normal Compiler. When the code will
     * be serialized this compiler will perform some obfuscations to make it
     * less readable and understandable.
     */
    class OCompiler : public Compiler {
      public:
        explicit OCompiler(asmjit::CodeHolder *code = nullptr) noexcept;

        asmjit::Error onAttach(asmjit::CodeHolder *code) noexcept override;
    };

} // namespace poly