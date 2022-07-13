#pragma once

#include <cstdint>

#include <functional>
#include <memory>
#include <random>
#include <type_traits>
#include <vector>

#include <LIEF/LIEF.hpp>
#include <asmjit/asmjit.h>

namespace poly {

    using namespace tcb;

    namespace impl {

        // CRTP pattern base class
        template <class A>
        class Crtp {
          protected:
            constexpr A *real() { return static_cast<A *>(this); }

            constexpr const A *real() const {
                return static_cast<const A *>(this);
            }
        };

        // Unique pointer static cast
        template <typename To, typename From>
        std::unique_ptr<To>
        static_unique_ptr_cast(std::unique_ptr<From> &&old) {
            return std::unique_ptr<To>{static_cast<To *>(old.release())};
        }

        // range specialization
        template <bool = true>
        struct range;

        // is_detected type trait
        template <class... Ts>
        using void_t = void;

        template <template <class...> class Trait, class Enabler, class... Args>
        struct is_detected_impl : std::false_type {};

        template <template <class...> class Trait, class... Args>
        struct is_detected_impl<Trait, void_t<Trait<Args...>>, Args...>
            : std::true_type {};

        template <template <class...> class Trait, class... Args>
        using is_detected_t =
            typename is_detected_impl<Trait, void, Args...>::type;

        // make_array
        template <typename... T>
        constexpr auto make_array(T &&...values) -> std::array<
            typename std::decay<typename std::common_type<T...>::type>::type,
            sizeof...(T)> {
            return std::array<typename std::decay<
                                  typename std::common_type<T...>::type>::type,
                              sizeof...(T)>{std::forward<T>(values)...};
        }

    } // namespace impl

    using Address = std::uint64_t;

    using RawCode = span<std::uint8_t>;

    using Compiler = asmjit::x86::Compiler;

    using Register = asmjit::x86::Gp;

    class RandomGenerator {
      public:
        ~RandomGenerator() = default;

        template <typename T>
        T get_random() noexcept;

        template <typename T>
        const T &random_from(const std::vector<T> &v) noexcept;

        template <typename T>
        T &random_from(std::vector<T> &v) noexcept;

        template <typename T>
        auto &random_from_it(const T &s, std::size_t n) noexcept;

        static RandomGenerator &get_generator() noexcept;

      private:
        RandomGenerator() noexcept;

        std::minstd_rand generator_;
    };

    //!
    //! Interface which represent a generic node of a binary tree.
    //!
    class TreeNode {
      public:
        //!
        //! \return the left child of this node.
        //!
        virtual TreeNode *left() const noexcept = 0;

        //!
        //! Modify the left child of this node.
        //! \param new_left the new node which will replace the old one.
        //! \return the old left child.
        //!
        virtual TreeNode *left(TreeNode *new_left) noexcept = 0;

        //!
        //! \return the right child of this node.
        //!
        virtual TreeNode *right() const noexcept = 0;

        //!
        //! Modify the right child of this node.
        //! \param new_right the new node which will replace the old one.
        //! \return the old right child.
        //!
        virtual TreeNode *right(TreeNode *new_right) noexcept = 0;

        //!
        //! \return the parent of this node.
        //!
        virtual TreeNode *parent() const noexcept = 0;

        //!
        //! Modify the parent of this node.
        //! \param new_parent the new node which will replace the old one.
        //! \return the old parent.
        //!
        virtual TreeNode *parent(TreeNode *new_parent) noexcept = 0;

        virtual ~TreeNode() {}

        //!
        //! \return true if this node has neither a left child nor a right
        //! child, otherwise returns false.
        //!
        virtual inline bool is_leaf() const noexcept {
            return left() == right() && left() == nullptr;
        }

        //!
        //! Cast this node to one of its derived classes.
        //!
        template <typename T>
        inline T *as() noexcept {
            return static_cast<T *>(this);
        }

        //!
        //! Cast this node to one of its derived classes.
        //!
        template <typename T>
        inline T *as() const noexcept {
            return static_cast<T *>(this);
        }

        //!
        //! Copy the tree which has this node as root.
        //! \return the new copy.
        //!
        virtual TreeNode *copy_tree() const noexcept;

        //!
        //! Visit a tree in post-order and perform actions on each node.
        //! \param root root of the tree to visit.
        //! \param fn function to call on each node. The node will be passed by
        //! parameter to the function.
        //!
        static void post_order(TreeNode *root,
                               std::function<void(TreeNode &node)> fn);

      protected:
        //!
        //! Copy only this node, without copying the entire tree.
        //! \return the newly created copy.
        //!
        virtual TreeNode *copy_node() const noexcept = 0;

      private:
        //!
        //! Helper method for the post-order visit. Retrieve the successor of
        //! the specified node in the visit.
        //! \param node node of which we must find the successor.
        //! \return nullptr if the node passed is the last node of the visit,
        //! otherwise returns a valid pointer to the successor.
        //!
        static TreeNode *post_order_successor(TreeNode *node) noexcept;
    };

    //!
    //! Concrete implementation of a TreeNode which will contain data of type T.
    //!
    template <typename T>
    class SpecializedTreeNode : public TreeNode {
      public:
        //!
        //! Build a new SpecializedTreeNode with no parent, left child and right
        //! child.
        //! \param data data to save inside the new node.
        //!
        SpecializedTreeNode<T>(T &data) noexcept;

        //!
        //! Build a new SpecializedTreeNode with no parent, left child and right
        //! child.
        //! \param data data to save inside the new node.
        //!
        SpecializedTreeNode<T>(const T &data) noexcept;

        //!
        //! Build a new SpecializedTreeNode.
        //! \param left left child of the new node.
        //! \param right right child of the new node.
        //! \param parent parent of the new node.
        //! \param data data to save inside the new node.
        //!
        SpecializedTreeNode<T>(TreeNode *left, TreeNode *right,
                               TreeNode *parent, T &data) noexcept;

        //!
        //! Build a new SpecializedTreeNode.
        //! \param left left child of the new node.
        //! \param right right child of the new node.
        //! \param parent parent of the new node.
        //! \param data data to save inside the new node.
        //!
        SpecializedTreeNode<T>(TreeNode *left, TreeNode *right,
                               TreeNode *parent, const T &data) noexcept;

        virtual inline ~SpecializedTreeNode<T>() {
            delete left_;
            delete right_;
        }

        inline TreeNode *left() const noexcept { return left_; }

        inline TreeNode *left(TreeNode *new_left) noexcept {
            TreeNode *res = left_;
            left_ = new_left;
            return res;
        }

        inline TreeNode *right() const noexcept { return right_; }

        inline TreeNode *right(TreeNode *new_right) noexcept {
            TreeNode *res = right_;
            right_ = new_right;
            return res;
        }

        inline TreeNode *parent() const noexcept { return parent_; }

        inline TreeNode *parent(TreeNode *new_parent) noexcept {
            TreeNode *res = parent_;
            parent_ = new_parent;
            return res;
        }

        //!
        //! \return the data contained in this node.
        //!
        inline T &data() noexcept { return data_; }

        //!
        //! Allocate a new SpecializedTreeNode with no parent, left child and
        //! right child.
        //! \param data data to save inside the new node.
        //! \return the newly created node.
        //!
        static inline SpecializedTreeNode<T> *build(const T &data) noexcept {
            return new SpecializedTreeNode<T>(data);
        }

      protected:
        T data_;
        TreeNode *left_;
        TreeNode *right_;
        TreeNode *parent_;

        inline TreeNode *copy_node() const noexcept {
            return SpecializedTreeNode<T>::build(this->data_);
        }
    };

} // namespace poly

#include "utils.tpp"