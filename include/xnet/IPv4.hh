#pragma once

#include <algorithm>
#include <array>
#include <concepts>
#include <iterator>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <vector>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <xnet/ByteOrder.hh>

namespace xnet::IPv4 {

struct Address
{
    static constexpr Address from_msbf(uint32_t addr)
    {
        std::array<uint8_t, 4> m_data{};

        for (uint8_t offset = 0; offset < 4; offset++) {
            uint32_t view = addr;
            uint32_t temp = addr;
            temp >>= (24 - offset * 8);
            temp &= 0xff;
            m_data[offset] = temp;
        }

        return Address(m_data);
    }

    constexpr Address() = default;

    constexpr Address(std::array<std::byte, 4> data) : m_data(data) {};
    constexpr Address(std::array<uint8_t, 4> data)
        : Address([data]() {
              std::array<std::byte, 4> out{};
              auto make_byte = [](uint8_t b) { return std::byte(b); };
              std::ranges::copy(
                  data | std::views::transform(make_byte), std::begin(out));
              return Address(out);
          }()) {};
    constexpr Address(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3)
        : Address(std::array<uint8_t, 4>{b0, b1, b2, b3})
    {
    }

    static constexpr bool equals(const Address &l, const Address &r)
    {
        return l.m_data == r.m_data;
    }

    std::array<std::byte, 4> data_msbf() const
    {
        return m_data;
    }

  private:
    std::array<std::byte, 4> m_data{};
};

constexpr bool operator==(const Address &l, const Address &r)
{
    return Address::equals(l, r);
}

struct Header
{
    uint8_t header_size;
    uint8_t type_of_service;
    uint16_t total_size;
    uint16_t identification;
    uint8_t flags : 3;
    uint16_t fragment_offset : 13;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t checksum;
    Address source_address;
    Address destination_address;
};

constexpr size_t minimal_header_size = []() {
    size_t output_bits = 0;
    output_bits += 4;  // Version
    output_bits += 4;  // IHL
    output_bits += 8;  // TOS
    output_bits += 16; // Total length
    output_bits += 16; // Identification
    output_bits += 3;  // Flags
    output_bits += 13; // Fragment Offset
    output_bits += 8;  // TTL
    output_bits += 8;  // Protocol
    output_bits += 16; // Header Checksum
    output_bits += 32; // Source Address
    output_bits += 32; // Destination Address
    return output_bits / 8;
}();

constexpr std::array<std::byte, minimal_header_size> serialize(const Header &h)
{
    uint8_t proto_header_size = h.header_size / sizeof(uint32_t);
    uint8_t ver_ihl = 0b01000000;
    ver_ihl |= proto_header_size;

    uint16_t flags_fragm_val = h.flags;
    // 0b0000000000000xxx -> 0bxxx0000000000000
    flags_fragm_val <<= 13;
    flags_fragm_val &= 0b1110000000000000;
    flags_fragm_val |= h.fragment_offset;

    std::array<std::byte, minimal_header_size> output{};
    uint16_t write_offset = 0;

    auto write_array =
        [&output, &write_offset]<size_t S>(const std::array<std::byte, S> &a) {
            std::copy(a.begin(), a.end(), output.begin() + write_offset);
            write_offset += a.size();
        };

    write_array(htobe<uint8_t>(ver_ihl));
    write_array(htobe<uint8_t>(h.type_of_service));
    write_array(htobe<uint16_t>(h.total_size));
    write_array(htobe<uint16_t>(h.identification));
    write_array(htobe<uint16_t>(flags_fragm_val));
    write_array(htobe<uint8_t>(h.time_to_live));
    write_array(htobe<uint8_t>(h.protocol));
    write_array(htobe<uint16_t>(h.checksum));
    write_array(h.source_address.data_msbf());
    write_array(h.destination_address.data_msbf());

    return output;
}

struct HeaderView
{
    constexpr HeaderView(std::span<const std::byte> data) : m_data(data)
    {
    }

    constexpr std::optional<Header> parse() const
    {
        if (is_not_safe_to_parse()) {
            return std::nullopt;
        }

        auto header_size = header_size_unsafe();
        auto type_of_service = type_of_service_unsafe();
        auto total_size = total_size_unsafe();
        auto identification = identification_unsafe();
        auto flags = flags_unsafe();
        auto fragment_offset = fragment_offset_unsafe();
        auto time_to_live = time_to_live_unsafe();
        auto protocol = protocol_unsafe();
        auto checksum = checksum_unsafe();
        auto source_address = source_address_unsafe();
        auto destination_address = destination_address_unsafe();

        Header output;
        output.header_size = header_size;
        output.type_of_service = type_of_service;
        output.total_size = total_size;
        output.identification = identification;
        output.flags = flags;
        output.fragment_offset = fragment_offset;
        output.time_to_live = time_to_live;
        output.protocol = protocol;
        output.checksum = checksum;
        output.source_address = source_address;
        output.destination_address = destination_address;
        return output;
    }

    constexpr std::optional<uint16_t> compute_checksum() const
    {
        if (is_not_valid()) {
            return std::nullopt;
        }

        return compute_checksum_unsafe();
    }

    constexpr bool verify_checksum() const
    {
        if (is_not_valid()) {
            return false;
        }

        return verify_checksum_unsafe();
    }

    constexpr bool is_not_safe_to_parse() const
    {
        if (m_data.size() < 1) {
            return true;
        }

        uint8_t header_size = header_size_unsafe();
        if (m_data.size() < header_size) {
            return true;
        }

        return false;
    }

    constexpr bool is_not_valid() const
    {
        if (is_not_safe_to_parse()) {
            return true;
        }

        uint8_t version_ihl = std::to_integer<uint8_t>(m_data[0]);
        uint8_t version = (version_ihl >> 4) & 0x0f;
        if (version != 4) {
            return true;
        }

        uint8_t header_size = header_size_unsafe();
        if (header_size < minimal_header_size) {
            return true;
        }

        constexpr uint8_t max_header_size = header_size_mask * sizeof(uint32_t);
        if (header_size > max_header_size) {
            assert(
                false &&
                "IHL cannot be greater then "
                "header_size_mask sizeof(uint32_t)");
            return true;
        }

        if (!verify_checksum_unsafe()) {
            return true;
        }

        return false;
    }

    constexpr std::optional<uint8_t> header_size() const
    {
        if (is_not_safe_to_parse()) {
            return std::nullopt;
        }

        return header_size_unsafe();
    }

    constexpr std::optional<uint8_t> type_of_service() const
    {
        if (is_not_safe_to_parse()) {
            return std::nullopt;
        }

        return type_of_service_unsafe();
    }

    constexpr std::optional<uint16_t> total_size() const
    {
        if (is_not_safe_to_parse()) {
            return std::nullopt;
        }

        auto total_size = total_size_unsafe();
        if (total_size > m_data.size()) {
            return std::nullopt;
        }

        return total_size;
    }

    constexpr std::optional<uint8_t> flags() const
    {
        if (is_not_safe_to_parse()) {
            return std::nullopt;
        }

        return flags_unsafe();
    }

    constexpr std::optional<uint16_t> fragment_offset() const
    {
        if (is_not_safe_to_parse()) {
            return std::nullopt;
        }

        return fragment_offset_unsafe();
    }

    constexpr std::optional<uint8_t> time_to_live() const
    {
        if (is_not_safe_to_parse()) {
            return std::nullopt;
        }

        return time_to_live_unsafe();
    }

    constexpr std::optional<uint8_t> protocol() const
    {
        if (is_not_safe_to_parse()) {
            return std::nullopt;
        }

        return protocol_unsafe();
    }

    constexpr std::optional<uint16_t> checksum() const
    {
        if (is_not_safe_to_parse()) {
            return std::nullopt;
        }

        return checksum_unsafe();
    }

    constexpr std::optional<Address> source_address() const
    {
        if (is_not_safe_to_parse()) {
            return std::nullopt;
        }

        return source_address_unsafe();
    }

    constexpr std::optional<Address> destination_address() const
    {
        if (is_not_safe_to_parse()) {
            return std::nullopt;
        }

        return destination_address_unsafe();
    }

    constexpr std::optional<std::span<const std::byte>> header_data() const
    {
        if (is_not_safe_to_parse()) {
            return std::nullopt;
        }
        return header_data_unsafe();
    }

  private:
    static constexpr uint8_t header_size_mask = 0b00001111;

    std::span<const std::byte> m_data;

    template <std::unsigned_integral I>
    constexpr I read_be_at_unsafe(size_t offset) const
    {
        std::array<std::byte, sizeof(I)> output_data{};
        std::ranges::copy(
            header_data_unsafe().subspan(offset, sizeof(I)),
            output_data.begin());
        return betoh<I>(output_data);
    }

    constexpr bool verify_checksum_unsafe() const
    {
        auto comp = compute_checksum_unsafe();
        comp = ~comp;
        auto checksum = checksum_unsafe();

        uint32_t carry_sum = comp + checksum;

        uint32_t nb_carry = carry_sum & 0xffff0000;
        nb_carry >>= (sizeof(uint16_t) * 8);

        uint16_t sum = carry_sum & 0xffff;
        sum += nb_carry;
        sum = ~sum;

        return sum == 0;
    }

    constexpr uint8_t header_size_unsafe() const
    {
        uint8_t version_ihl = to_integer<uint8_t>(m_data[0]);
        return (version_ihl & header_size_mask) * sizeof(uint32_t);
    }

    constexpr uint8_t type_of_service_unsafe() const
    {
        return read_be_at_unsafe<uint8_t>(1);
    }

    constexpr uint16_t total_size_unsafe() const
    {
        return read_be_at_unsafe<uint16_t>(2);
    }

    constexpr uint8_t flags_unsafe() const
    {
        uint8_t flags = read_be_at_unsafe<uint8_t>(6);
        flags &= 0b11100000;
        flags >>= 5;
        flags &= 0b00000111;
        return flags;
    }

    constexpr uint16_t fragment_offset_unsafe() const
    {
        uint16_t output = read_be_at_unsafe<uint16_t>(6);
        output &= uint16_t(0b0001111111111111);
        return output;
    }

    constexpr uint8_t time_to_live_unsafe() const
    {
        return read_be_at_unsafe<uint8_t>(8);
    }

    constexpr uint8_t protocol_unsafe() const
    {
        return read_be_at_unsafe<uint8_t>(9);
    }

    constexpr uint16_t checksum_unsafe() const
    {
        return read_be_at_unsafe<uint16_t>(10);
    }

    constexpr Address source_address_unsafe() const
    {
        auto H = header_data_unsafe();
        auto addr_data = H.subspan(12, 4);
        std::array<std::byte, 4> data{};
        std::ranges::copy(addr_data, data.begin());
        return Address(data);
    }

    constexpr Address destination_address_unsafe() const
    {
        auto H = header_data_unsafe();
        auto addr_data = H.subspan(16, 4);
        std::array<std::byte, 4> data{};
        std::ranges::copy(addr_data, data.begin());
        return Address(data);
    }

    constexpr std::optional<uint16_t> identification() const
    {
        if (is_not_safe_to_parse()) {
            return std::nullopt;
        }
        return identification_unsafe();
    }

    constexpr uint16_t identification_unsafe() const
    {
        return read_be_at_unsafe<uint16_t>(4);
    }

    constexpr std::span<const std::byte> header_data_unsafe() const
    {
        auto size = header_size_unsafe();
        return m_data.subspan(0, size);
    }

    constexpr uint16_t compute_checksum_unsafe() const
    {
        uint32_t carry_output = 0;
        uint8_t header_size = header_size_unsafe();
        assert(header_size % sizeof(uint16_t) == 0);
        uint8_t nb_uint16 = header_size / sizeof(uint16_t);

        constexpr size_t header_checksum_u16_pos = 5;

        for (size_t u16_offset = 0; u16_offset < header_checksum_u16_pos;
             u16_offset++) {
            size_t offset = u16_offset * sizeof(uint16_t);
            carry_output += read_be_at_unsafe<uint16_t>(offset);
        }

        for (size_t u16_offset = header_checksum_u16_pos + 1;
             u16_offset < nb_uint16;
             u16_offset++) {

            size_t offset = u16_offset * sizeof(uint16_t);
            carry_output += read_be_at_unsafe<uint16_t>(offset);
        }

        uint32_t nb_carry = carry_output & 0xffff0000;
        nb_carry >>= (sizeof(uint16_t) * 8);

        uint16_t output = carry_output & 0xffff;
        output += nb_carry;

        return ~output;
    }
};

struct PacketView
{
    constexpr PacketView(std::span<const std::byte> data) : m_data(data)
    {
    }

    constexpr bool is_valid() const
    {
        return !is_not_valid();
    }

    constexpr bool is_not_valid() const
    {
        HeaderView header = header_view();
        if (header.is_not_valid()) {
            return true;
        }

        if (!payload_data().has_value()) {
            return true;
        }

        return false;
    }

    constexpr HeaderView header_view() const
    {
        return HeaderView(m_data);
    }

    constexpr std::optional<std::span<const std::byte>> payload_data() const
    {
        auto header_size_opt = header_view().header_size();
        auto payload_size_opt = payload_size();
        if (!payload_size_opt || !header_size_opt) {
            return std::nullopt;
        }

        auto header_size = header_size_opt.value();
        auto payload_size = payload_size_opt.value();

        if (m_data.size() < header_size + payload_size) {
            return std::nullopt;
        }

        return m_data.subspan(header_size, payload_size);
    }

    constexpr std::optional<std::vector<std::byte>> clone_data() const
    {
        if (is_not_valid()) {
            return std::nullopt;
        }

        auto header_size_opt = header_view().header_size();
        auto payload_size_opt = payload_size();

        if (!header_size_opt || !payload_size_opt) {
            return std::nullopt;
        }

        size_t output_raw_packet_data_size =
            header_size_opt.value() + payload_size_opt.value();

        if (m_data.size() < output_raw_packet_data_size) {
            return std::nullopt;
        }

        std::vector<std::byte> output;
        output.reserve(output_raw_packet_data_size);

        std::ranges::copy(
            m_data | std::views::take(output_raw_packet_data_size),
            std::back_inserter(output));

        return output;
    }

  private:
    std::span<const std::byte> m_data;

    constexpr std::optional<uint16_t> payload_size() const
    {
        auto header_size_opt = header_view().header_size();
        auto total_length_opt = header_view().total_size();
        if (!header_size_opt || !total_length_opt) {
            return std::nullopt;
        }

        auto header_size = header_size_opt.value();
        auto total_length = total_length_opt.value();

        if (total_length < header_size) {
            /*
             * Total Length is the length of the datagram, measured in octets,
             * including internet header and data.
             *
             * so it cannot be less than header_size (IHL)
             */
            return std::nullopt;
        }

        return total_length - header_size;
    }
};
} // namespace xnet::IPv4
