#pragma once

#include <array>
#include <concepts>
#include <type_traits>

#include <cstddef>
#include <cstdint>

namespace xnet {

template <std::unsigned_integral I>
constexpr auto htobe(std::type_identity_t<I> n)
{
    std::array<std::byte, sizeof(I)> output;
    if constexpr (sizeof(I) == 1) {
        output[0] = std::byte(n);
        return output;
    }

    for (uint8_t byte_idx = 0; byte_idx < sizeof(I); byte_idx++) {
        size_t shift_size = (sizeof(I) - 1 - byte_idx) * 8;
        I mask = 0xff;
        mask <<= shift_size;
        I val = n & mask;
        val >>= shift_size;
        output[byte_idx] = std::byte(val);
    }

    return output;
}

template <std::unsigned_integral I>
constexpr auto htole(std::type_identity_t<I> n)
{
    std::array<std::byte, sizeof(I)> output;
    if constexpr (sizeof(I) == 1) {
        output[0] = std::byte(n);
        return output;
    }

    for (uint8_t byte_idx = 0; byte_idx < sizeof(I); byte_idx++) {
        size_t shift_size = byte_idx * 8;
        I mask = 0xff;
        mask <<= shift_size;
        I val = n & mask;
        val >>= shift_size;
        output[byte_idx] = std::byte(val);
    }

    return output;
}

template <std::unsigned_integral I>
constexpr I betoh(const std::array<std::byte, sizeof(I)> data)
{
    I output = 0;
    for (std::byte b : data) {
        if constexpr (sizeof(I) != 1) {
            output <<= 8;
        }
        output |= std::to_integer<I>(b);
    }
    return output;
}

template <std::unsigned_integral I>
constexpr I letoh(const std::array<std::byte, sizeof(I)> data)
{
    I output = 0;
    size_t off = 0;
    for (std::byte b : data) {
        I part = std::to_integer<I>(b);
        output |= part << (8 * off);
        off++;
    }
    return output;
}

} // namespace xnet
