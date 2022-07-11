#include <catch2/catch.hpp>

#include <limits>

#include <asmjit/asmjit.h>

#include <poly/ocompiler.hpp>

using Rand32BitGen = Catch::Generators::RandomIntegerGenerator<int>;

inline int get(Rand32BitGen &gen) {
    auto res = gen.get();
    gen.next();
    return res;
}

void generate_not_code(asmjit::x86::Compiler &c) {
    auto *func_node = c.addFunc(asmjit::FuncSignatureT<int, int>());

    auto arg = c.newInt32();
    func_node->setArg(0, arg);

    c.not_(arg);
    c.ret(arg);

    c.endFunc();
}

void generate_and_code(asmjit::x86::Compiler &c) {
    auto *func_node = c.addFunc(asmjit::FuncSignatureT<int, int, int>());

    auto arg1 = c.newInt32();
    auto arg2 = c.newInt32();
    func_node->setArg(0, arg1);
    func_node->setArg(1, arg2);

    c.and_(arg1, arg2);
    c.ret(arg1);

    c.endFunc();
}

void generate_or_code(asmjit::x86::Compiler &c) {
    auto *func_node = c.addFunc(asmjit::FuncSignatureT<int, int, int>());

    auto arg1 = c.newInt32();
    auto arg2 = c.newInt32();
    func_node->setArg(0, arg1);
    func_node->setArg(1, arg2);

    c.or_(arg1, arg2);
    c.ret(arg1);

    c.endFunc();
}

void generate_xor_code(asmjit::x86::Compiler &c) {
    auto *func_node = c.addFunc(asmjit::FuncSignatureT<int, int, int>());

    auto arg1 = c.newInt32();
    auto arg2 = c.newInt32();
    func_node->setArg(0, arg1);
    func_node->setArg(1, arg2);

    c.xor_(arg1, arg2);
    c.ret(arg1);

    c.endFunc();
}

void generate_add_code(asmjit::x86::Compiler &c) {
    auto *func_node = c.addFunc(asmjit::FuncSignatureT<int, int, int>());

    auto arg1 = c.newInt32();
    auto arg2 = c.newInt32();
    func_node->setArg(0, arg1);
    func_node->setArg(1, arg2);

    c.add(arg1, arg2);
    c.ret(arg1);

    c.endFunc();
}

void generate_sub_code(asmjit::x86::Compiler &c) {
    auto *func_node = c.addFunc(asmjit::FuncSignatureT<int, int, int>());

    auto arg1 = c.newInt32();
    auto arg2 = c.newInt32();
    func_node->setArg(0, arg1);
    func_node->setArg(1, arg2);

    c.sub(arg1, arg2);
    c.ret(arg1);

    c.endFunc();
}

TEST_CASE("Obfuscate assembly code", "[unit][ocompiler]") {
    asmjit::JitRuntime rt;

    asmjit::CodeHolder code_cc{};
    code_cc.init(rt.environment());
    asmjit::x86::Compiler cc{&code_cc};

    asmjit::CodeHolder code_oc{};
    code_oc.init(rt.environment());
    poly::OCompiler oc{&code_oc};

    SECTION("Not operation") {
        generate_not_code(cc);
        cc.finalize();

        generate_not_code(oc);
        oc.finalize();

        auto raw_code_size_cc = code_cc.textSection()->realSize();
        auto raw_code_size_oc = code_oc.textSection()->realSize();

        REQUIRE(raw_code_size_cc <= raw_code_size_oc);

        using Not = int (*)(int);

        Not not_cc;
        asmjit::Error err = rt.add(&not_cc, &code_cc);
        REQUIRE(err == asmjit::kErrorOk);

        Not not_oc;
        err = rt.add(&not_oc, &code_oc);
        REQUIRE(err == asmjit::kErrorOk);

        Rand32BitGen gen{std::numeric_limits<int>::min(),
                         std::numeric_limits<int>::max()};
        auto arg = get(gen);

        CHECK(not_cc(arg) == (~arg));
        REQUIRE(not_cc(arg) == not_oc(arg));
    }

    SECTION("And operation") {
        generate_and_code(cc);
        cc.finalize();

        generate_and_code(oc);
        oc.finalize();

        auto raw_code_size_cc = code_cc.textSection()->realSize();
        auto raw_code_size_oc = code_oc.textSection()->realSize();

        REQUIRE(raw_code_size_cc <= raw_code_size_oc);

        using And = int (*)(int, int);

        And and_cc;
        asmjit::Error err = rt.add(&and_cc, &code_cc);
        REQUIRE(err == asmjit::kErrorOk);

        And and_oc;
        err = rt.add(&and_oc, &code_oc);
        REQUIRE(err == asmjit::kErrorOk);

        Rand32BitGen gen{std::numeric_limits<int>::min(),
                         std::numeric_limits<int>::max()};
        auto arg1 = get(gen), arg2 = get(gen);

        CHECK(and_cc(arg1, arg2) == (arg1 & arg2));
        REQUIRE(and_cc(arg1, arg2) == and_oc(arg1, arg2));
    }

    SECTION("Or operation") {
        generate_or_code(cc);
        cc.finalize();

        generate_or_code(oc);
        oc.finalize();

        auto raw_code_size_cc = code_cc.textSection()->realSize();
        auto raw_code_size_oc = code_oc.textSection()->realSize();

        REQUIRE(raw_code_size_cc <= raw_code_size_oc);

        using Or = int (*)(int, int);

        Or or_cc;
        asmjit::Error err = rt.add(&or_cc, &code_cc);
        REQUIRE(err == asmjit::kErrorOk);

        Or or_oc;
        err = rt.add(&or_oc, &code_oc);
        REQUIRE(err == asmjit::kErrorOk);

        Rand32BitGen gen{std::numeric_limits<int>::min(),
                         std::numeric_limits<int>::max()};
        auto arg1 = get(gen), arg2 = get(gen);

        CHECK(or_cc(arg1, arg2) == (arg1 | arg2));
        REQUIRE(or_cc(arg1, arg2) == or_oc(arg1, arg2));
    }

    SECTION("Xor operation") {
        generate_xor_code(cc);
        cc.finalize();

        generate_xor_code(oc);
        oc.finalize();

        auto raw_code_size_cc = code_cc.textSection()->realSize();
        auto raw_code_size_oc = code_oc.textSection()->realSize();

        REQUIRE(raw_code_size_cc <= raw_code_size_oc);

        using Xor = int (*)(int, int);

        Xor xor_cc;
        asmjit::Error err = rt.add(&xor_cc, &code_cc);
        REQUIRE(err == asmjit::kErrorOk);

        Xor xor_oc;
        err = rt.add(&xor_oc, &code_oc);
        REQUIRE(err == asmjit::kErrorOk);

        Rand32BitGen gen{std::numeric_limits<int>::min(),
                         std::numeric_limits<int>::max()};
        auto arg1 = get(gen), arg2 = get(gen);

        CHECK(xor_cc(arg1, arg2) == (arg1 ^ arg2));
        REQUIRE(xor_cc(arg1, arg2) == xor_oc(arg1, arg2));
    }

    SECTION("Add operation") {
        generate_add_code(cc);
        cc.finalize();

        generate_add_code(oc);
        oc.finalize();

        auto raw_code_size_cc = code_cc.textSection()->realSize();
        auto raw_code_size_oc = code_oc.textSection()->realSize();

        REQUIRE(raw_code_size_cc <= raw_code_size_oc);

        using Add = int (*)(int, int);

        Add add_cc;
        asmjit::Error err = rt.add(&add_cc, &code_cc);
        REQUIRE(err == asmjit::kErrorOk);

        Add add_oc;
        err = rt.add(&add_oc, &code_oc);
        REQUIRE(err == asmjit::kErrorOk);

        Rand32BitGen gen{std::numeric_limits<int>::min(),
                         std::numeric_limits<int>::max()};
        auto arg1 = get(gen), arg2 = get(gen);

        CHECK(add_cc(arg1, arg2) == (arg1 + arg2));
        REQUIRE(add_cc(arg1, arg2) == add_oc(arg1, arg2));
    }

    SECTION("Sub operation") {
        generate_sub_code(cc);
        cc.finalize();

        generate_sub_code(oc);
        oc.finalize();

        auto raw_code_size_cc = code_cc.textSection()->realSize();
        auto raw_code_size_oc = code_oc.textSection()->realSize();

        REQUIRE(raw_code_size_cc <= raw_code_size_oc);

        using Sub = int (*)(int, int);

        Sub sub_cc;
        asmjit::Error err = rt.add(&sub_cc, &code_cc);
        REQUIRE(err == asmjit::kErrorOk);

        Sub sub_oc;
        err = rt.add(&sub_oc, &code_oc);
        REQUIRE(err == asmjit::kErrorOk);

        Rand32BitGen gen{std::numeric_limits<int>::min(),
                         std::numeric_limits<int>::max()};
        auto arg1 = get(gen), arg2 = get(gen);

        CHECK(sub_cc(arg1, arg2) == (arg1 - arg2));
        REQUIRE(sub_cc(arg1, arg2) == sub_oc(arg1, arg2));
    }
}