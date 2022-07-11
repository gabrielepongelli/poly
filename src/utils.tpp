#pragma once

#include <iterator>
#include <random>
#include <vector>

#include "poly/utils.hpp"

namespace poly {

    template <typename T>
    T RandomGenerator::get_random() noexcept {
        std::uniform_int_distribution<T> distribution{};
        return distribution(generator_);
    }

    template <>
    bool RandomGenerator::get_random<bool>() noexcept;

    template <typename T>
    const T &RandomGenerator::random_from(const std::vector<T> &v) noexcept {
        std::uniform_int_distribution<std::size_t> distribution{0,
                                                                v.size() - 1};
        return v.at(distribution(generator_));
    }

    template <typename T>
    T &RandomGenerator::random_from(std::vector<T> &v) noexcept {
        std::uniform_int_distribution<std::size_t> distribution{0,
                                                                v.size() - 1};
        return v[distribution(generator_)];
    }

    template <typename T>
    auto &RandomGenerator::random_from_it(const T &s, std::size_t n) noexcept {
        auto it = std::begin(s);

        std::uniform_int_distribution<std::size_t> distribution{0, n - 1};
        auto pos = distribution(generator_);

        while (pos-- > 0) {
            std::next(it);
        }

        return *it;
    }

    static RandomGenerator &get_generator() noexcept;

    template <typename T>
    SpecializedTreeNode<T>::SpecializedTreeNode(T &data) noexcept
        : SpecializedTreeNode<T>{nullptr, nullptr, nullptr, data} {}

    template <typename T>
    SpecializedTreeNode<T>::SpecializedTreeNode(const T &data) noexcept
        : SpecializedTreeNode<T>{nullptr, nullptr, nullptr, data} {}

    template <typename T>
    SpecializedTreeNode<T>::SpecializedTreeNode(TreeNode *left, TreeNode *right,
                                                TreeNode *parent,
                                                T &data) noexcept
        : left_{left}, right_{right}, parent_{parent}, data_{data} {}

    template <typename T>
    SpecializedTreeNode<T>::SpecializedTreeNode(TreeNode *left, TreeNode *right,
                                                TreeNode *parent,
                                                const T &data) noexcept
        : left_{left}, right_{right}, parent_{parent}, data_{data} {}

} // namespace poly