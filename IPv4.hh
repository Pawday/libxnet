#pragma once

#include <algorithm>
#include <array>
#include <concepts>
#include <iterator>
#include <optional>
#include <ranges>
#include <span>
#include <string>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace IPv4 {

struct Address
{
    static Address from_msbf(uint32_t addr)
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

    Address() = default;

    Address(std::array<std::byte, 4> data) : m_data(data) {};
    Address(std::array<uint8_t, 4> data)
        : Address([data]() {
              std::array<std::byte, 4> out{};
              auto make_byte = [](uint8_t b) { return std::byte(b); };
              std::ranges::copy(
                  data | std::views::transform(make_byte), std::begin(out));
              return out;
          }()) {};

    static bool equals(const Address &l, const Address &r)
    {
        uint32_t l_val;
        uint32_t r_val;

        std::memcpy(&l_val, l.m_data.data(), sizeof(uint32_t));
        std::memcpy(&r_val, r.m_data.data(), sizeof(uint32_t));

        return l_val == r_val;
    }

    std::array<std::byte, 4> data_msbf() const
    {
        return m_data;
    }

  private:
    std::array<std::byte, 4> m_data{};
};

inline bool operator==(const Address &l, const Address &r)
{
    return Address::equals(l, r);
}

struct Header
{
    uint8_t header_size;
    uint8_t type_of_service;
    uint16_t total_size;
    uint16_t identification;
    uint8_t flags;
    uint16_t fragment_offset;
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

struct HeaderView
{
    HeaderView(std::span<const std::byte> data) : m_data(data)
    {
    }

    std::optional<Header> parse() const
    {
        auto header_size_opt = header_size();
        auto type_of_service_opt = type_of_service();
        auto total_size_opt = total_size();
        auto identification_opt = identification();
        auto flags_opt = flags();
        auto fragment_offset_opt = fragment_offset();
        auto time_to_live_opt = time_to_live();
        auto protocol_opt = protocol();
        auto checksum_opt = checksum();
        auto source_address_opt = source_address();
        auto destination_address_opt = destination_address();

        bool parsed = true;
        parsed = parsed && header_size_opt.has_value();
        parsed = parsed && type_of_service_opt.has_value();
        parsed = parsed && total_size_opt.has_value();
        parsed = parsed && identification_opt.has_value();
        parsed = parsed && flags_opt.has_value();
        parsed = parsed && fragment_offset_opt.has_value();
        parsed = parsed && time_to_live_opt.has_value();
        parsed = parsed && protocol_opt.has_value();
        parsed = parsed && checksum_opt.has_value();
        parsed = parsed && source_address_opt.has_value();
        parsed = parsed && destination_address_opt.has_value();

        if (!parsed) {
            return std::nullopt;
        }

        Header output;
        output.header_size = header_size_opt.value();
        output.type_of_service = type_of_service_opt.value();
        output.total_size = total_size_opt.value();
        output.identification = identification_opt.value();
        output.flags = flags_opt.value();
        output.fragment_offset = fragment_offset_opt.value();
        output.time_to_live = time_to_live_opt.value();
        output.protocol = protocol_opt.value();
        output.checksum = checksum_opt.value();
        output.source_address = source_address_opt.value();
        output.destination_address = destination_address_opt.value();
        return output;
    }

    std::optional<uint16_t> compute_checksum() const
    {
        uint32_t carry_output = 0;
        auto header_size_opt = header_size();
        if (!header_size_opt) {
            return std::nullopt;
        }

        uint8_t header_size = header_size_opt.value();
        assert(header_size % sizeof(uint16_t) == 0);
        uint8_t nb_uint16 = header_size / sizeof(uint16_t);
        if (nb_uint16 < 10) {
            return std::nullopt;
        }

        constexpr size_t header_checksum_u16_pos = 5;

        for (size_t u16_offset = 0; u16_offset < header_checksum_u16_pos;
             u16_offset++) {
            size_t offset = u16_offset * sizeof(uint16_t);

            auto val_opt = read_be_at<uint16_t>(offset);
            if (!val_opt.has_value()) {
                return std::nullopt;
            }
            uint16_t value = val_opt.value();
            carry_output += value;
        }

        for (size_t u16_offset = header_checksum_u16_pos + 1;
             u16_offset < nb_uint16;
             u16_offset++) {

            size_t offset = u16_offset * sizeof(uint16_t);

            auto val_opt = read_be_at<uint16_t>(offset);
            if (!val_opt.has_value()) {
                return std::nullopt;
            }
            uint16_t value = val_opt.value();
            carry_output += value;
        }

        uint32_t nb_carry = carry_output & 0xffff0000;
        nb_carry >>= (sizeof(uint16_t) * 8);

        uint16_t output = carry_output & 0xffff;
        output += nb_carry;

        return ~output;
    }

    bool verify_checksum() const
    {
        auto checksum_opt = checksum();
        auto computed_checksum_opt = compute_checksum();
        if (!checksum_opt.has_value() || !computed_checksum_opt.has_value()) {
            return false;
        }

        auto comp = computed_checksum_opt.value();
        comp = ~comp;
        auto checksum = checksum_opt.value();

        uint32_t carry_sum = comp + checksum;

        uint32_t nb_carry = carry_sum & 0xffff0000;
        nb_carry >>= (sizeof(uint16_t) * 8);

        uint16_t sum = carry_sum & 0xffff;
        sum += nb_carry;
        sum = ~sum;

        return sum == 0;
    }

    bool is_not_valid() const
    {
        if (m_data.size() < 1) {
            return true;
        }

        uint8_t version_ihl = std::to_integer<uint8_t>(m_data[0]);
        uint8_t version = (version_ihl >> 4) & 0x0f;
        if (version != 4) {
            return true;
        }

        uint8_t header_size = (version_ihl & 0x0f) * sizeof(uint32_t);
        if (header_size < 20) {
            return true;
        }

        constexpr uint8_t max_header_size = 0b1111 * sizeof(uint32_t);
        if (header_size > max_header_size) {
            assert(
                false &&
                "IHL cannot be greater then 0b1111 * sizeof(uint32_t)");
            return true;
        }

        if (m_data.size() < header_size) {
            return true;
        }

        return false;
    }

    std::optional<uint8_t> header_size() const
    {
        if (is_not_valid()) {
            return std::nullopt;
        }

        uint8_t version_ihl = std::to_integer<uint8_t>(m_data[0]);
        return (version_ihl & 0x0f) * sizeof(uint32_t);
    }

    std::optional<uint8_t> type_of_service() const
    {
        return read_be_at<uint8_t>(1);
    }

    std::optional<uint16_t> total_size() const
    {
        if (is_not_valid()) {
            return std::nullopt;
        }

        auto total_size = read_be_at<uint16_t>(2);
        if (!total_size) {
            return std::nullopt;
        }
        if (total_size.value() > m_data.size()) {
            return std::nullopt;
        }

        return total_size.value();
    }

    std::optional<uint16_t> identification() const
    {
        return read_be_at<uint16_t>(4);
    }

    std::optional<uint8_t> flags() const
    {
        auto flags_dirty = read_be_at<uint8_t>(6);
        if (!flags_dirty.has_value()) {
            return std::nullopt;
        }

        uint8_t flags = flags_dirty.value();
        flags &= 0b11100000;
        flags >>= 5;
        flags &= 0b00000111;
        return flags;
    }

    std::optional<uint16_t> fragment_offset() const
    {
        auto frag_offset_dirty = read_be_at<uint16_t>(6);
        if (!frag_offset_dirty.has_value()) {
            return std::nullopt;
        }

        uint16_t output = frag_offset_dirty.value();
        output &= uint16_t(0b0001111111111111);
        return output;
    }

    std::optional<uint8_t> time_to_live() const
    {
        return read_be_at<uint8_t>(8);
    }

    std::optional<uint8_t> protocol() const
    {
        return read_be_at<uint8_t>(9);
    }

    std::optional<uint16_t> checksum() const
    {
        return read_be_at<uint16_t>(10);
    }

    std::optional<Address> source_address() const
    {
        if (is_not_valid()) {
            return std::nullopt;
        }

        auto H = header_data();
        if (!H) {
            return std::nullopt;
        }

        auto addr_data = H.value().subspan(12, 4);
        std::array<std::byte, 4> data{};
        std::ranges::copy(addr_data, data.begin());
        return Address(data);
    }

    std::optional<Address> destination_address() const
    {
        if (is_not_valid()) {
            return std::nullopt;
        }

        auto H = header_data();
        if (!H) {
            return std::nullopt;
        }

        auto addr_data = H.value().subspan(16, 4);
        std::array<std::byte, 4> data{};
        std::ranges::copy(addr_data, data.begin());
        return Address(data);
    }

  private:
    std::span<const std::byte> m_data;

    template <std::unsigned_integral I>
    std::optional<I> read_be_at(size_t offset) const
    {
        if (is_not_valid()) {
            return std::nullopt;
        }

        auto header_opt = header_data();
        if (!header_opt) {
            return std::nullopt;
        }

        auto output_data = header_opt.value().subspan(offset, sizeof(I));

        I output = 0;
        for (std::byte b : output_data) {
            if constexpr (sizeof(I) != 1) {
                output <<= 8;
            }
            output |= std::to_integer<I>(b);
        }
        return output;
    }

    std::optional<std::span<const std::byte>> header_data() const
    {
        if (is_not_valid()) {
            return std::nullopt;
        }

        auto size = header_size();
        if (!size) {
            return std::nullopt;
        }

        if (m_data.size() < size.value()) {
            return std::nullopt;
        }

        return m_data.subspan(0, size.value());
    }
};

struct PacketView
{
    PacketView(std::span<const std::byte> data) : m_data(data)
    {
    }

    bool is_valid() const
    {
        return !is_not_valid();
    }

    bool is_not_valid() const
    {
        HeaderView header(m_data);
        if (header.is_not_valid()) {
            return true;
        }

        if (!header.verify_checksum()) {
            return true;
        }

        if (!payload_data().has_value()) {
            return true;
        }

        return false;
    }

    std::optional<Header> parse_header() const
    {
        return HeaderView(m_data).parse();
    }

    std::optional<std::span<const std::byte>> payload_data() const
    {
        auto header_size_opt = header_size();
        auto payload_size_opt = payload_size();
        if (!payload_size_opt || !header_size_opt) {
            return std::nullopt;
        }

        auto header_size = header_size_opt.value();
        auto payload_size = payload_size_opt.value();

        if (m_data.size() < header_size + payload_size) {
            return std::nullopt;
        }

        return m_data.subspan(
            header_size_opt.value(), payload_size_opt.value());
    }

    std::optional<uint16_t> total_size() const
    {
        return HeaderView(m_data).total_size();
    }

    std::optional<std::vector<std::byte>> clone_data() const
    {
        if (is_not_valid()) {
            return std::nullopt;
        }

        auto header_size_opt = header_size();
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

    std::optional<uint16_t> header_size() const
    {
        return HeaderView(m_data).header_size();
    }

    std::optional<uint16_t> payload_size() const
    {
        auto header_size_opt = header_size();
        auto total_length_opt = total_size();
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
} // namespace IPv4
