#include <cstdint>

#include <algorithm>
#include <limits>
#include <vector>

#include <asmjit/asmjit.h>
#include <catch2/catch.hpp>

#include <engine/code_container.hpp>

TEST_CASE("Produce machine code", "[unit][code_container]") {
    poly::CodeContainer cc;

    SECTION("Retrieve virtual registers") {

        SECTION("Retrieve register with zero size") {
            auto &reg = cc.get_virtual_register(0);

            REQUIRE(reg.isNone());
        }

        SECTION("Retrieve multiple different virtual registers") {

            std::uint8_t n =
                Catch::Generators::RandomIntegerGenerator<std::uint8_t>(0, 255)
                    .get();

            std::vector<const asmjit::Operand *> results;

            for (std::uint8_t i = 0; i < n; i++) {
                results.push_back(&cc.get_virtual_register());
            }

            auto size = results.size();
            for (std::uint8_t i = 0; i < size - 1; i++) {
                auto op = results.back();
                results.pop_back();

                auto it = std::find(results.begin(), results.end(), op);

                REQUIRE(it == results.end());
            }
        }
    }

    SECTION("Mark registers") {
        // must be a memory operand
        auto &mem = cc.get_virtual_register(10);

        CHECK(mem.isMem());
        CHECK(cc.mark_as_untouchable(mem) ==
              poly::EditableCodeError::kInvalidOperand);

        while (true) {
            auto &reg = cc.get_virtual_register();

            if (!reg.isPhysReg()) {
                continue;
            }

            CHECK(cc.mark_as_untouchable(reg) ==
                  poly::EditableCodeError::kNone);
            REQUIRE(cc.mark_as_free(reg) ==
                    poly::EditableCodeError::kOperandIsUntouchable);

            break;
        }
    }

    SECTION("Generate code that can be executed") {
        auto &b = cc.builder();

        auto a_arg = b.zax();
        auto b_arg = b.zbx();

        asmjit::FuncDetail func;
        func.init(asmjit::FuncSignatureT<int, int, int>(),
                  asmjit::Environment::host());
        asmjit::FuncFrame frame;
        frame.init(func);
        asmjit::FuncArgsAssignment args(&func);
        args.assignAll(a_arg, b_arg);
        args.updateFuncFrame(frame);
        frame.finalize();

        b.emitProlog(frame);
        b.emitArgsAssignment(frame, args);
        b.add(a_arg, b_arg);
        b.emitEpilog(frame);
        b.ret();

        // first and second arguments won't be used
        auto res = cc.produce_raw(0, 0);

        void *buffer;
        asmjit::JitAllocator all;
        all.alloc(&buffer, &buffer, res.size());

        for (auto i = 0; i < res.size(); i++) {
            *(static_cast<std::uint8_t *>(buffer) + i) = res[i];
        }

        Catch::Generators::RandomIntegerGenerator<unsigned int> gen(
            0, std::numeric_limits<unsigned int>::max() / 2);
        unsigned int a1 = gen.get();
        gen.next();
        unsigned int a2 = gen.get();

        typedef unsigned int (*SumFn)(unsigned int, unsigned int);
        auto sum = reinterpret_cast<SumFn>(buffer);

        REQUIRE(a1 + a2 == sum(a1, a2));
    }
}