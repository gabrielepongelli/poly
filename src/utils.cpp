#include "engine/utils.hpp"

#include <memory>
#include <random>

namespace poly {

    RandomGenerator &RandomGenerator::get_generator() {
        static std::unique_ptr<RandomGenerator> common_gen;

        if (common_gen.get() == nullptr) {
            common_gen =
                std::unique_ptr<RandomGenerator>(new RandomGenerator());
        }

        return *common_gen;
    }

    RandomGenerator::RandomGenerator() : generator_{std::random_device{}()} {}

} // namespace poly
