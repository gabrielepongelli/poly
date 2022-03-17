#pragma once

#include <iterator>
#include <random>
#include <vector>

#include "engine/utils.hpp"

namespace poly {

    template <typename T>
    T RandomGenerator::get_random() {
        std::uniform_int_distribution<T> distribution{};
        return distribution(generator_);
    }

    template <>
    bool RandomGenerator::get_random<bool>();

    template <typename T>
    const T &RandomGenerator::random_from(const std::vector<T> &v) {
        std::uniform_int_distribution<std::size_t> distribution{0,
                                                                v.size() - 1};
        return v.at(distribution(generator_));
    }

    template <typename T>
    T &RandomGenerator::random_from(std::vector<T> &v) {
        std::uniform_int_distribution<std::size_t> distribution{0,
                                                                v.size() - 1};
        return v[distribution(generator_)];
    }

    template <typename T>
    auto &RandomGenerator::random_from_it(const T &s, std::size_t n) {
        auto it = std::begin(s);

        std::uniform_int_distribution<std::size_t> distribution{0, n - 1};
        auto pos = distribution(generator_);

        while (pos-- > 0) {
            std::next(it);
        }

        return *it;
    }

    static RandomGenerator &get_generator();

} // namespace poly