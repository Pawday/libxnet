#include <algorithm>
#include <array>
#include <format>
#include <iostream>
#include <iterator>
#include <limits>
#include <optional>
#include <ranges>
#include <span>

#include <cstddef>
#include <cstdint>

#include <xnet/ByteOrder.hh>
#include <xnet/IPv4.hh>
#include <xnet/UDP.hh>

namespace xnet {

namespace UDP {

struct HeaderCreateInfo
{
    IPv4::Address pseudo_source{};
    IPv4::Address pseudo_destination{};
    uint8_t pseudo_protocol{};
    uint16_t source_port{};
    uint16_t destination_port{};
    std::span<const std::byte> data;
};

constexpr std::optional<Header> create_valid_header(HeaderCreateInfo info)
{
    if (info.data.size() > std::numeric_limits<uint16_t>::max() - header_size) {
        return std::nullopt;
    }
    uint16_t udp_length = info.data.size() + header_size;

    auto extract_u16_pair_be_from =
        [](IPv4::Address a) -> std::array<uint16_t, 2> {
        auto data = a.data_msbf();

        std::array<std::byte, 2> first_data{};
        std::ranges::copy(
            data | std::views::drop(0) | std::views::take(2),
            std::begin(first_data));

        std::array<std::byte, 2> second_data{};
        std::ranges::copy(
            data | std::views::drop(2) | std::views::take(2),
            std::begin(second_data));

        std::array<uint16_t, 2> output{};
        output[0] = betoh<uint16_t>(first_data);
        output[1] = betoh<uint16_t>(second_data);
        return output;
    };

    uint32_t carry_checksum = 0;

    // <pseudo_header>
    for (uint16_t num : extract_u16_pair_be_from(info.pseudo_source)) {
        carry_checksum += num;
    }

    for (uint16_t num : extract_u16_pair_be_from(info.pseudo_destination)) {
        carry_checksum += num;
    }

    carry_checksum += info.pseudo_protocol;
    carry_checksum += udp_length;
    // </pseudo_header>

    // <header>
    carry_checksum += info.source_port;
    carry_checksum += info.destination_port;
    carry_checksum += udp_length; // Yes, again
    carry_checksum += 0;
    // </header>

    auto data_u16_at = [&info](size_t u16_offset) -> uint16_t {
        std::array<std::byte, 2> output_data{};
        auto source = info.data.subspan(u16_offset * 2, 2);
        std::ranges::copy(source, std::begin(output_data));
        return betoh<uint16_t>(output_data);
    };
    size_t data_nb_u16s = info.data.size() / sizeof(uint16_t);
    for (size_t u16_offset = 0; u16_offset < data_nb_u16s; u16_offset++) {
        carry_checksum += data_u16_at(u16_offset);
    }

    if ((info.data.size() % sizeof(uint16_t)) != 0) {
        uint16_t last_n = std::to_integer<uint8_t>(info.data.back());
        last_n <<= 8;
        carry_checksum += last_n;
    }

    uint32_t checksum_nb_carry = carry_checksum & 0xffff0000;
    checksum_nb_carry >>= (sizeof(uint16_t) * 8);
    checksum_nb_carry &= 0xffff;

    uint16_t checksum = carry_checksum & 0xffff;
    checksum += checksum_nb_carry;
    checksum = ~checksum;

    Header output;
    output.source_port = info.source_port;
    output.destination_port = info.destination_port;
    output.length = udp_length;
    output.checksumm = checksum;
    return output;
}

} // namespace UDP
} // namespace xnet
