#include "poly/utils.hpp"

#include <functional>
#include <memory>
#include <random>

namespace poly {

    RandomGenerator &RandomGenerator::get_generator() noexcept {
        static std::unique_ptr<RandomGenerator> common_gen;

        if (common_gen.get() == nullptr) {
            common_gen =
                std::unique_ptr<RandomGenerator>(new RandomGenerator());
        }

        return *common_gen;
    }

    RandomGenerator::RandomGenerator() noexcept
        : generator_{std::random_device{}()} {}

    template <>
    bool RandomGenerator::get_random<bool>() noexcept {
        std::uniform_int_distribution<int> distribution{0, 1};
        return distribution(generator_);
    }

    TreeNode *TreeNode::copy_tree() const noexcept {
        TreeNode *new_root = this->copy_node();
        TreeNode *clone = new_root;
        const TreeNode *original = this;

        while (clone != nullptr) {
            if (original->left() != nullptr && clone->left() == nullptr) {
                clone->left(original->left()->copy_node());
                clone->left()->parent(clone);
                original = original->left();
                clone = clone->left();
            } else if (original->right() != nullptr &&
                       clone->right() == nullptr) {
                clone->right(original->right()->copy_node());
                clone->right()->parent(clone);
                original = original->right();
                clone = clone->right();
            } else {
                original = original->parent();
                clone = clone->parent();
            }
        }

        return new_root;
    }

    void TreeNode::post_order(TreeNode *root,
                              std::function<void(TreeNode &node)> fn) {
        if (root != nullptr) {
            while (root->left() != nullptr) {
                root = root->left();
            }

            while (root != nullptr) {
                fn(*root);
                root = post_order_successor(root);
            }
        }
    }

    TreeNode *TreeNode::post_order_successor(TreeNode *node) noexcept {
        if (node == nullptr || node->parent() == nullptr) {
            return nullptr;
        }

        if (node->parent()->right() == node ||
            node->parent()->right() == nullptr) {
            return node->parent();
        } else {
            node = node->parent()->right();
            while (node != nullptr &&
                   (node->left() != nullptr || node->right() != nullptr)) {
                if (node->left() != nullptr) {
                    node = node->left();
                } else {
                    node = node->right();
                }
            }
        }

        return node;
    }

} // namespace poly
