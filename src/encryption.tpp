#pragma once

#include <cstdint>

#include <algorithm>
#include <bitset>

#include <asmjit/asmjit.h>

#include "poly/encryption.hpp"
#include "poly/enums.hpp"
#include "poly/host_properties.hpp"
#include "poly/utils.hpp"

namespace poly {

    template <std::size_t bytes, std::size_t check, typename T>
    Block<bytes>
    BlockBuilder<bytes, check, T>::build(std::uint8_t *ptr) noexcept {
        Block<bytes> res = 0;

        for (std::size_t i = 0; i < bytes; i++) {
            res |= std::bitset<bytes>(ptr[i]) << (8 * i);
        }

        return res;
    }

    template <std::size_t bytes, std::size_t check, typename T>
    void BlockBuilder<bytes, check, T>::to_bytes(Block<bytes> &b,
                                                 std::uint8_t *ptr) noexcept {
        for (std::size_t i = 0; i < bytes; i++) {
            ptr[i] = (std::uint8_t)((b >> (i * 8)).to_ulong());
        }
    }

    template <std::size_t bytes, std::size_t check>
    Block<bytes>
    BlockBuilder<bytes, check,
                 impl::range<(bytes == 2 || bytes == 4 || bytes == 8)>>::
        build(std::uint8_t *ptr) noexcept {
        Block<bytes> res = 0;

        for (std::size_t i = 0; i < bytes; i++) {
            res |= static_cast<Block<bytes>>(ptr[i]) << (8 * i);
        }

        return res;
    }

    template <std::size_t bytes, std::size_t check>
    void BlockBuilder<bytes, check,
                      impl::range<(bytes == 2 || bytes == 4 || bytes == 8)>>::
        to_bytes(Block<bytes> &b, std::uint8_t *ptr) noexcept {
        for (std::size_t i = 0; i < bytes; i++) {
            ptr[i] = (std::uint8_t)(b >> (i * 8));
        }
    }

    template <std::size_t check>
    inline Block<1>
    BlockBuilder<1, check, impl::range<>>::build(std::uint8_t *ptr) noexcept {
        return *ptr;
    }

    template <std::size_t check>
    inline void BlockBuilder<1, check, impl::range<>>::to_bytes(
        Block<1> &b, std::uint8_t *ptr) noexcept {
        *ptr = b;
    }

    namespace impl {

        template <class Enc>
        template <std::uint8_t size>
        Error CipherImpl<CipherMode::kCBC, Enc>::encrypt(
            RawCode &src, RawCode &dst,
            const EncryptionSecret<size> &secret) noexcept {
            auto working_data = secret.iv;
            auto extra_data_src = src.size() % size;
            auto extra_data_dst = dst.size() % size;
            auto for_limit = std::min<>(src.size() - extra_data_src,
                                        dst.size() - extra_data_dst);
            for (std::size_t i = 0; i < for_limit; i = i + size) {
                working_data =
                    working_data ^ BlockBuilder<size>::build(src.data() + i);
                Enc::template encrypt<size>(secret, working_data);
                BlockBuilder<size>::to_bytes(working_data, dst.data() + i);
            }

            if (src.data() != dst.data()) {
                auto min = std::min<>(src.size(), dst.size());
                std::copy(src.data() + for_limit, src.data() + min,
                          dst.data() + for_limit);
            }

            if (extra_data_src != 0 || extra_data_dst != 0) {
                return Error::kNotAligned;
            } else {
                return Error::kNone;
            }
        }

        template <class Enc>
        template <std::uint8_t size>
        Error CipherImpl<CipherMode::kCBC, Enc>::assemble_decryption(
            const EncryptionSecret<size> &secret, Compiler &c,
            const Register &data_ptr, std::size_t data_len,
            const asmjit::Label &exit_label) noexcept {
            auto extra_data = data_len % size;
            data_len = data_len - extra_data;

            auto Loop = c.newLabel();
            auto counter = c.newUInt64();
            auto iv = c.newUInt64();
            auto working_register = c.newUInt64();
            auto key = c.newUInt64();

            c.mov(key, secret.key);
            c.mov(counter, data_len);

            // if counter = 0 then exit
            c.test(counter, counter);
            c.jz(exit_label);
            c.mov(iv, secret.iv);

            // bind the Loop label here
            c.bind(Loop);
            c.mov(working_register, asmjit::x86::ptr(data_ptr));
            c.xor_(working_register, working_register);
            c.add(working_register, asmjit::x86::ptr(data_ptr));

            // encryption algorithm
            Enc::template assemble_decryption<size>(key, working_register, c);

            c.xor_(working_register, iv);

            // c.mov(iv, asmjit::x86::ptr(data_ptr));
            c.xor_(iv, iv);
            c.add(iv, asmjit::x86::ptr(data_ptr));

            c.mov(asmjit::x86::ptr(data_ptr), working_register);
            c.add(data_ptr, size);
            c.sub(counter, size);
            c.cmp(counter, 0);

            // if counter > 0 then goto Loop
            c.jg(Loop);

            if (extra_data != 0) {
                return Error::kNotAligned;
            } else {
                return Error::kNone;
            }
        }

    } // namespace impl

    template <std::uint8_t size>
    EncryptionSecret<size>::EncryptionSecret(Block<size> iv,
                                             Block<size> key) noexcept
        : iv{iv}, key{key} {}

    template <>
    template <std::uint8_t size>
    void EncryptionAlgorithm<EncryptionAlgorithmType::kNone>::encrypt(
        const EncryptionSecret<size> &secret, Block<size> &data) noexcept {}

    template <>
    template <std::uint8_t size>
    void
    EncryptionAlgorithm<EncryptionAlgorithmType::kNone>::assemble_decryption(
        Register &key, Register &data, Compiler &c) noexcept {}

    template <>
    inline void
    EncryptionAlgorithm<EncryptionAlgorithmType::kXor>::encrypt<kByteWordSize>(
        const EncryptionSecret<kByteWordSize> &secret,
        Block<kByteWordSize> &data) noexcept {
        data = data ^ secret.key;
    }

    template <>
    inline void
    EncryptionAlgorithm<EncryptionAlgorithmType::kXor>::assemble_decryption<
        kByteWordSize>(Register &key, Register &data, Compiler &c) noexcept {
        c.xor_(data, key);
    }

    template <CipherMode M, class Enc>
    template <std::uint8_t size>
    inline Error
    Cipher<M, Enc>::encrypt(RawCode &src, RawCode &dst,
                            const EncryptionSecret<size> &secret) noexcept {
        static_assert(
            impl::supports_encrypt<Enc, const EncryptionSecret<size> &,
                                   Block<size> &>::value,
            "Enc template parameter must implement this static method: "
            "template <std::uint8_t size> void encrypt(EncryptionSecret<size> "
            "&, Block<size> &)");

        return impl::CipherImpl<M, Enc>::template encrypt<size>(src, dst,
                                                                secret);
    }

    template <CipherMode M, class Enc>
    template <std::uint8_t size>
    inline Error
    Cipher<M, Enc>::encrypt(RawCode &data,
                            const EncryptionSecret<size> &secret) noexcept {
        static_assert(
            impl::supports_encrypt<Enc, const EncryptionSecret<size> &,
                                   Block<size> &>::value,
            "Enc template parameter must implement this static method: "
            "template <std::uint8_t size> void encrypt(EncryptionSecret<size> "
            "&, Block<size> &)");

        return impl::CipherImpl<M, Enc>::template encrypt<size>(data, data,
                                                                secret);
    }

    template <CipherMode M, class Enc>
    template <std::uint8_t size>
    inline Error Cipher<M, Enc>::assemble_decryption(
        const EncryptionSecret<size> &secret, Compiler &c,
        const Register &data_ptr, std::size_t data_len,
        const asmjit::Label &exit_label) noexcept {
        static_assert(
            impl::supports_assemble_decryption<Enc, Register &, Register &,
                                               Compiler &>::value,
            "Enc template parameter must implement this static method: "
            "template <std::uint8_t size> void assemble_decryption(Register &, "
            "Register &, Compiler &)");

        return impl::CipherImpl<M, Enc>::template assemble_decryption<size>(
            secret, c, data_ptr, data_len, exit_label);
    }

} // namespace poly