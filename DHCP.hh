#pragma once

#include "IPv4.hh"
#include <algorithm>
#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <endian.h>
#include <iterator>
#include <optional>
#include <ranges>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace dhcp {

inline constexpr size_t header_size = []() {
    size_t output = 0;
    output += 1;   // Message op code
    output += 1;   // Hardware address type
    output += 1;   // Hardware address length
    output += 1;   // Hops
    output += 4;   // Transaction ID
    output += 2;   // Cliend seconds
    output += 2;   // Flags
    output += 4;   // Old client IP address
    output += 4;   // New client IP address
    output += 4;   // IP address of next server
    output += 4;   // Relay agent IP address
    output += 16;  // Client hardware address
    output += 64;  // Server host name
    output += 128; // Boot file name
    return output;
}();

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

struct PacketView
{
    PacketView(std::span<const std::byte> data) : m_data(data)
    {
    }

#if 0
    static std::span<uint8_t> trim_options(std::span<uint8_t> options_data)
    {
        if (options_data.size() == 0) {
            return options_data;
        }

        size_t options_size = options_data.size();
        while (options_size != 0 && options_data[options_size - 1] == 0) {
            options_size--;
        }

        return options_data.subspan(0, options_size);
    }
#endif

    bool validate_header() const
    {
        return headers().has_value();
    }

    std::optional<std::span<const std::byte, header_size>> headers() const
    {
        if (m_data.size() < header_size) {
            return std::nullopt;
        }

        return std::span<const std::byte, header_size>(
            m_data.template subspan<0, header_size>());
    }

    std::optional<std::span<const std::byte>> options() const
    {
        if (!validate_header()) {
            return std::nullopt;
        }

        std::span<const std::byte> options_data = m_data.subspan(header_size);
        if (options_data.size() < 4) {
            return std::nullopt;
        }

        std::array<uint8_t, 4> cookie_data{};
        std::ranges::copy(
            options_data | std::views::take(4) |
                std::views::transform(std::to_integer<uint8_t>),
            std::begin(cookie_data));
        std::array<uint8_t, 4> valid_cookie_data{99, 130, 83, 99};

        if (valid_cookie_data != cookie_data) {
            return std::nullopt;
        }

        auto output = options_data.subspan(4);
        if (!validate_options(output)) {
            return std::nullopt;
        }

        return output;
    }

  private:
    std::span<const std::byte> m_data;

    static bool validate_options(std::span<const std::byte> options_data)
    {
        size_t read_offset = 0;
        while (read_offset != options_data.size()) {
            if (read_offset > options_data.size()) {
                return false;
            }

            const uint8_t op_code =
                std::to_integer<uint8_t>(options_data[read_offset]);

            switch (op_code) {
            case 0:
            case 0xff:
                read_offset++;
                continue;
            }

            const uint8_t op_size = std::to_integer<uint8_t>(
                options_data[read_offset + sizeof(op_code)]);
            read_offset += sizeof(op_code) + sizeof(op_size);
            read_offset += op_size;
        }

        return true;
    }
};

enum class OperationCode
{
    BOOTREQUEST,
    BOOTREPLY
};

struct ClientHardwareAddr
{
    ClientHardwareAddr() = default;

    ClientHardwareAddr(const std::array<std::byte, 16> &data) : m_data(data)
    {
    }

    ClientHardwareAddr(const std::array<uint8_t, 16> &data)
        : ClientHardwareAddr([data]() {
              std::array<std::byte, 16> out{};
              auto make_byte = [](uint8_t b) { return std::byte(b); };
              std::ranges::copy(
                  data | std::views::transform(make_byte), std::begin(out));
              return out;
          }()) {};

    std::array<std::byte, 16> data() const
    {
        return m_data;
    }

  private:
    std::array<std::byte, 16> m_data{};
};

struct Header
{
    OperationCode op{};
    uint8_t htype{};
    uint8_t hlen{};
    uint8_t hops{};
    uint32_t xid{};
    uint16_t secs{};
    uint16_t flags{};
    IPv4::Address ciaddr{};
    IPv4::Address yiaddr{};
    IPv4::Address siaddr{};
    IPv4::Address giaddr{};
    ClientHardwareAddr chaddr{};
    std::array<char, 64> sname{};
    std::array<char, 128> file{};

    bool is_sname_valid() const
    {
        return std::ranges::any_of(sname, [](char c) { return c == 0; });
    }

    std::string sname_string() const
    {
        if (not is_sname_valid()) {
            throw std::runtime_error("Non zero terminated dhcp::Header::sname");
        }
        return std::string(sname.data());
    }

    bool is_file_valid() const
    {
        return std::ranges::any_of(file, [](char c) { return c == 0; });
    }

    std::string file_string() const
    {
        if (not is_file_valid()) {
            throw std::runtime_error("Non zero terminated dhcp::Header::file");
        }
        return std::string(file.data());
    }
};

inline std::vector<std::byte> serialize(const Header &h)
{
    using B = std::byte;
    std::vector<std::byte> output;

    output.reserve(header_size);

    switch (h.op) {
        using enum OperationCode;
    case BOOTREQUEST:
        output.push_back(B(1));
        break;
    case BOOTREPLY:
        output.push_back(B(2));
        break;
    }

    output.push_back(B(h.htype));
    output.push_back(B(h.hlen));
    output.push_back(B(h.hops));

    std::ranges::copy(htobe<uint32_t>(h.xid), std::back_inserter(output));
    std::ranges::copy(htobe<uint16_t>(h.secs), std::back_inserter(output));
    std::ranges::copy(htobe<uint16_t>(h.flags), std::back_inserter(output));
    std::ranges::copy(h.ciaddr.data_msbf(), std::back_inserter(output));
    std::ranges::copy(h.yiaddr.data_msbf(), std::back_inserter(output));
    std::ranges::copy(h.siaddr.data_msbf(), std::back_inserter(output));
    std::ranges::copy(h.giaddr.data_msbf(), std::back_inserter(output));
    std::ranges::copy(h.chaddr.data(), std::back_inserter(output));

    auto make_byte = [](char c) { return std::byte(c); };

    std::ranges::copy(
        h.sname | std::views::transform(make_byte), std::back_inserter(output));
    std::ranges::copy(
        h.file | std::views::transform(make_byte), std::back_inserter(output));

    return output;
}

struct HeaderView
{
    HeaderView(std::span<const std::byte> data) : m_msg(data)
    {
    }

    std::optional<Header> parse() const
    {
        auto op_opt = op();
        auto htype_opt = htype();
        auto hlen_opt = hlen();
        auto hops_opt = hops();
        auto xid_opt = xid();
        auto secs_opt = secs();
        auto flags_opt = flags();
        auto ciaddr_opt = ciaddr();
        auto yiaddr_opt = yiaddr();
        auto siaddr_opt = siaddr();
        auto giaddr_opt = giaddr();
        auto chaddr_opt = chaddr();
        auto sname_opt = sname();
        auto file_opt = file();

        bool parsed = true;
        parsed = parsed && op_opt.has_value();
        parsed = parsed && htype_opt.has_value();
        parsed = parsed && hlen_opt.has_value();
        parsed = parsed && hops_opt.has_value();
        parsed = parsed && xid_opt.has_value();
        parsed = parsed && secs_opt.has_value();
        parsed = parsed && flags_opt.has_value();
        parsed = parsed && ciaddr_opt.has_value();
        parsed = parsed && yiaddr_opt.has_value();
        parsed = parsed && siaddr_opt.has_value();
        parsed = parsed && giaddr_opt.has_value();
        parsed = parsed && chaddr_opt.has_value();
        parsed = parsed && sname_opt.has_value();
        parsed = parsed && file_opt.has_value();

        if (!parsed) {
            return std::nullopt;
        }

        Header output;
        output.op = op_opt.value();
        output.htype = htype_opt.value();
        output.hlen = hlen_opt.value();
        output.hops = hops_opt.value();
        output.xid = xid_opt.value();
        output.secs = secs_opt.value();
        output.flags = flags_opt.value();
        output.ciaddr = ciaddr_opt.value();
        output.yiaddr = yiaddr_opt.value();
        output.siaddr = siaddr_opt.value();
        output.giaddr = giaddr_opt.value();
        output.chaddr = chaddr_opt.value();
        output.sname = sname_opt.value();
        output.file = file_opt.value();
        return output;
    }

    std::optional<OperationCode> op() const
    {
        auto op_val = read_be_at<uint8_t>(0);
        if (!op_val) {
            return std::nullopt;
        }

        switch (op_val.value()) {
            using enum OperationCode;
        case 1:
            return BOOTREQUEST;
        case 2:
            return BOOTREPLY;
        }

        return std::nullopt;
    }

    std::optional<uint8_t> htype() const
    {
        return read_be_at<uint8_t>(1);
    }

    std::optional<uint8_t> hlen() const
    {
        return read_be_at<uint8_t>(2);
    }

    std::optional<uint8_t> hops() const
    {
        return read_be_at<uint8_t>(3);
    }

    std::optional<uint32_t> xid() const
    {
        return read_be_at<uint32_t>(4);
    }

    std::optional<uint16_t> secs() const
    {
        return read_be_at<uint16_t>(8);
    }

    std::optional<uint16_t> flags() const
    {
        return read_be_at<uint16_t>(10);
    }

    std::optional<IPv4::Address> ciaddr() const
    {
        return read_ipv4_addr_at(12);
    }

    std::optional<IPv4::Address> yiaddr() const
    {
        return read_ipv4_addr_at(16);
    }

    std::optional<IPv4::Address> siaddr() const
    {
        return read_ipv4_addr_at(20);
    }

    std::optional<IPv4::Address> giaddr() const
    {
        return read_ipv4_addr_at(24);
    }

    std::optional<ClientHardwareAddr> chaddr() const
    {
        auto ho = m_msg.headers();
        if (!ho) {
            return std::nullopt;
        }
        auto header = ho.value();

        std::array<std::byte, 16> addr_data{};

        std::ranges::copy(header.subspan(28, 16), std::begin(addr_data));

        return ClientHardwareAddr(addr_data);
    }

    std::optional<std::array<char, 64>> sname() const
    {
        auto ho = m_msg.headers();
        if (!ho) {
            return std::nullopt;
        }
        auto header = ho.value();
        std::array<char, 64> output{};

        std::ranges::copy(
            header.subspan(44, 64) |
                std::views::transform(std::to_integer<char>),
            std::begin(output));

        if (std::ranges::none_of(output, [](char b) { return b == 0; })) {
            return std::nullopt;
        }

        return output;
    }

    std::optional<std::string> sname_string() const
    {
        auto sname_data_op = sname();
        if (!sname_data_op) {
            return std::nullopt;
        }
        auto sname_data = sname_data_op.value();
        return std::string(sname_data.data());
    }

    std::optional<std::array<char, 128>> file() const
    {
        auto ho = m_msg.headers();
        if (!ho) {
            return std::nullopt;
        }
        auto header = ho.value();
        std::array<char, 128> output{};

        std::ranges::copy(
            header.subspan(108, 128) |
                std::views::transform(std::to_integer<char>),
            std::begin(output));

        if (std::ranges::none_of(output, [](char b) { return b == 0; })) {
            return std::nullopt;
        }

        return output;
    }

    std::optional<std::string> file_string() const
    {
        auto sname_data_op = file();
        if (!sname_data_op) {
            return std::nullopt;
        }
        auto sname_data = sname_data_op.value();
        return std::string(sname_data.data());
    }

  private:
    PacketView m_msg;

    template <std::unsigned_integral I>
    std::optional<I> read_be_at(size_t offset) const
    {
        auto ho = m_msg.headers();
        if (!ho) {
            return std::nullopt;
        }

        auto output_data = ho.value().subspan(offset, sizeof(I));

        I output = 0;
        for (std::byte b : output_data) {
            if constexpr (sizeof(I) != 1) {
                output <<= 8;
            }
            output |= std::to_integer<I>(b);
        }
        return output;
    }

    std::optional<IPv4::Address> read_ipv4_addr_at(size_t offset) const
    {
        auto be_addr = read_be_at<uint32_t>(offset);
        if (!be_addr.has_value()) {
            return std::nullopt;
        }
        return IPv4::Address::from_msbf(be_addr.value());
    }
};

} // namespace dhcp
