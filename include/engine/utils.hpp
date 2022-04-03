#pragma once

#include <cstdint>

#include <memory>
#include <random>
#include <type_traits>
#include <vector>

namespace poly {

    namespace impl {

        // CRTP pattern base class
        template <class A>
        class crtp_single_param {
          protected:
            constexpr A *real() { return static_cast<A *>(this); }
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
        using is_detected =
            typename is_detected_impl<Trait, void, Args...>::type;

    } // namespace impl

    using Address = std::uint64_t;

    using RawCode = std::vector<std::uint8_t>;

    class RandomGenerator {
      public:
        ~RandomGenerator() = default;

        template <typename T>
        T get_random();

        template <typename T>
        const T &random_from(const std::vector<T> &v);

        template <typename T>
        T &random_from(std::vector<T> &v);

        template <typename T>
        auto &random_from_it(const T &s, std::size_t n);

        static RandomGenerator &get_generator();

      private:
        RandomGenerator();

        std::minstd_rand generator_;
    };

} // namespace poly

#include "utils.tpp"