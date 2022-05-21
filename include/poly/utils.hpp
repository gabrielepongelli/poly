#pragma once

#include <cstdint>

#include <memory>
#include <random>
#include <type_traits>
#include <vector>

#include <LIEF/LIEF.hpp>
#include <asmjit/asmjit.h>

namespace poly {

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

    using RawCode = LIEF::span<std::uint8_t>;

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

} // namespace poly

#include "utils.tpp"