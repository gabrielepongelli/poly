#pragma once

#include <cstdint>
#include <type_traits>

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

    } // namespace impl

    using Address = std::uint64_t;

} // namespace poly
