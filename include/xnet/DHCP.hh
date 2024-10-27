#pragma once

#include <algorithm>
#include <array>
#include <concepts>
#include <endian.h>
#include <iterator>
#include <optional>
#include <ranges>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <xnet/ByteOrder.hh>
#include <xnet/IPv4.hh>

namespace xnet::DHCP {

constexpr size_t header_size = []() {
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

enum class OperationCode
{
    BOOTREQUEST,
    BOOTREPLY
};

struct ClientHardwareAddr
{
    constexpr ClientHardwareAddr() = default;

    constexpr ClientHardwareAddr(const std::array<std::byte, 16> &data)
        : m_data(data)
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
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    xnet::IPv4::Address ciaddr;
    xnet::IPv4::Address yiaddr;
    xnet::IPv4::Address siaddr;
    xnet::IPv4::Address giaddr;
    ClientHardwareAddr chaddr;
    std::array<std::byte, 64> sname;
    std::array<std::byte, 128> file;
};

constexpr std::array<std::byte, header_size> serialize(const Header &h)
{
    using B = std::byte;
    std::array<std::byte, header_size> output;
    uint16_t write_offset = 0;
    auto write_array = [&output, &write_offset]<typename T, size_t S>(
                           const std::array<T, S> &a) {
        auto make_byte = [](T c) { return std::byte(c); };
        std::ranges::copy(
            a | std::views::transform(make_byte),
            output.begin() + write_offset);
        write_offset += a.size();
    };

    write_array(htobe<uint8_t>(h.op));
    write_array(htobe<uint8_t>(h.htype));
    write_array(htobe<uint8_t>(h.hlen));
    write_array(htobe<uint8_t>(h.hops));
    write_array(htobe<uint32_t>(h.xid));
    write_array(htobe<uint16_t>(h.secs));
    write_array(htobe<uint16_t>(h.flags));
    write_array(h.ciaddr.data_msbf());
    write_array(h.yiaddr.data_msbf());
    write_array(h.siaddr.data_msbf());
    write_array(h.giaddr.data_msbf());
    write_array(h.chaddr.data());
    write_array(h.sname);
    write_array(h.file);

    return output;
}

struct HeaderView
{
    constexpr HeaderView(std::span<const std::byte> data) : m_data(data)
    {
    }

    constexpr bool not_safe_to_parse() const
    {
        return m_data.size() < header_size;
    }

    constexpr std::optional<Header> parse() const
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

    constexpr std::optional<uint8_t> op() const
    {
        return read_be_at<uint8_t>(0);
    }

    constexpr std::optional<uint8_t> htype() const
    {
        return read_be_at<uint8_t>(1);
    }

    constexpr std::optional<uint8_t> hlen() const
    {
        return read_be_at<uint8_t>(2);
    }

    constexpr std::optional<uint8_t> hops() const
    {
        return read_be_at<uint8_t>(3);
    }

    constexpr std::optional<uint32_t> xid() const
    {
        return read_be_at<uint32_t>(4);
    }

    constexpr std::optional<uint16_t> secs() const
    {
        return read_be_at<uint16_t>(8);
    }

    constexpr std::optional<uint16_t> flags() const
    {
        return read_be_at<uint16_t>(10);
    }

    constexpr std::optional<xnet::IPv4::Address> ciaddr() const
    {
        return read_ipv4_addr_at(12);
    }

    constexpr std::optional<xnet::IPv4::Address> yiaddr() const
    {
        return read_ipv4_addr_at(16);
    }

    constexpr std::optional<xnet::IPv4::Address> siaddr() const
    {
        return read_ipv4_addr_at(20);
    }

    constexpr std::optional<xnet::IPv4::Address> giaddr() const
    {
        return read_ipv4_addr_at(24);
    }

    constexpr std::optional<ClientHardwareAddr> chaddr() const
    {
        if (not_safe_to_parse()) {
            return std::nullopt;
        }
        std::array<std::byte, 16> addr_data{};
        std::ranges::copy(m_data.subspan(28, 16), std::begin(addr_data));
        return ClientHardwareAddr(addr_data);
    }

    constexpr std::optional<std::array<std::byte, 64>> sname() const
    {
        if (not_safe_to_parse()) {
            return std::nullopt;
        }
        std::array<std::byte, 64> output{};
        std::ranges::copy(m_data.subspan(44, 64), std::begin(output));
        return output;
    }

    constexpr std::optional<std::array<std::byte, 128>> file() const
    {
        if (not_safe_to_parse()) {
            return std::nullopt;
        }
        std::array<std::byte, 128> output{};
        std::ranges::copy(m_data.subspan(108, 128), std::begin(output));
        return output;
    }

  private:
    std::span<const std::byte> m_data;

    template <std::unsigned_integral I>
    constexpr std::optional<I> read_be_at(size_t offset) const
    {
        if (not_safe_to_parse()) {
            return std::nullopt;
        }

        std::array<std::byte, sizeof(I)> output_data;
        std::ranges::copy(
            m_data.subspan(offset, sizeof(I)), output_data.begin());
        return betoh<I>(output_data);
    }

    constexpr std::optional<xnet::IPv4::Address>
        read_ipv4_addr_at(size_t offset) const
    {
        if (not_safe_to_parse()) {
            return std::nullopt;
        }
        std::array<std::byte, 4> addr_data;
        std::ranges::copy(m_data.subspan(offset, 4), addr_data.begin());
        return xnet::IPv4::Address(addr_data);
    }
};

struct PacketView
{
    constexpr PacketView(std::span<const std::byte> data) : m_data(data)
    {
    }

    constexpr std::optional<HeaderView> header_view() const
    {
        auto header = header_data();
        if (!header.has_value()) {
            return std::nullopt;
        }

        return HeaderView(header.value());
    }

  private:
#if 0
    static constexpr std::span<uint8_t> trim_options(std::span<uint8_t> options_data)
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

    constexpr bool validate_header() const
    {
        return header_data().has_value();
    }

    constexpr std::optional<std::span<const std::byte, header_size>>
        header_data() const
    {
        if (m_data.size() < header_size) {
            return std::nullopt;
        }

        return std::span<const std::byte, header_size>(
            m_data.template subspan<0, header_size>());
    }

    constexpr std::optional<std::span<const std::byte>> options_data() const
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

    static constexpr bool
        validate_options(std::span<const std::byte> options_data)
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

} // namespace xnet::DHCP
