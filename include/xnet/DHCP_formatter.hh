#pragma once

#include <algorithm>
#include <array>
#include <bitset>
#include <format>
#include <iterator>
#include <ranges>
#include <string>

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "DHCP.hh"

template <>
struct std::formatter<xnet::DHCP::OperationCode, char>
{
    template <class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext &ctx)
    {
        return ctx.begin();
    }

    template <typename FmtContext>
    constexpr auto
        format(const xnet::DHCP::OperationCode &code, FmtContext &ctx) const
    {
        auto output = ctx.out();

        switch (code) {
            using enum xnet::DHCP::OperationCode;
        case BOOTREQUEST:
            return std::format_to(output, "BOOTREQUEST");
        case BOOTREPLY:
            return std::format_to(output, "BOOTREPLY");
        }

        throw std::format_error("Unknown dhcp opcode");
    }
};

template <>
struct std::formatter<xnet::DHCP::ClientHardwareAddr, char>
{
    template <class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext &ctx)
    {
        return ctx.begin();
    }

    template <typename FmtContext>
    auto format(
        const xnet::DHCP::ClientHardwareAddr &addr, FmtContext &ctx) const
    {
        auto output = ctx.out();

        auto data_bytes = addr.data();

        bool first = true;
        for (auto b : data_bytes) {
            if (!first) {
                output = std::format_to(output, ":");
            }
            first = false;
            output =
                std::format_to(output, "{:02x}", std::to_integer<uint8_t>(b));
        }

        return output;
    }
};

template <>
struct std::formatter<xnet::DHCP::Header, char>
{
    template <class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext &ctx)
    {
        return ctx.begin();
    }

    template <typename FmtContext>
    auto format(const xnet::DHCP::Header &header, FmtContext &ctx) const
    {
        auto output = ctx.out();

        constexpr size_t sname_data_size =
            std_array_size_v<decltype(xnet::DHCP::Header::sname)>;
        constexpr size_t file_data_size =
            std_array_size_v<decltype(xnet::DHCP::Header::file)>;

        constexpr size_t sname_data_string_size =
            sname_data_size * (sizeof("xx") - 1) /* each byte as string */
            + sname_data_size - 1                /* comma between */
            + 1 /* zero term */;

        constexpr size_t file_data_string_size =
            file_data_size * (sizeof("xx") - 1) /* each byte as string */
            + file_data_size - 1                /* comma between */
            + 1 /* zero term */;

        auto json_pritify = [](char &c) {
            switch (c) {
            case '\"':
            case '\\':
                c = '.';
                return;
            }

            if (c == '\0') {
                return;
            }

            if (std::isprint(c)) {
                return;
            }
            c = '.';
        };

        constexpr size_t sname_size = xnet::DHCP::Header().sname.size();
        std::array<char, sname_size + 1> sname_string_ascii{};
        std::ranges::copy(
            header.sname | std::views::transform(std::to_integer<char>),
            std::begin(sname_string_ascii));
        std::ranges::for_each(sname_string_ascii, json_pritify);
        sname_string_ascii.back() = '\0';

        constexpr size_t file_size = xnet::DHCP::Header().file.size();
        std::array<char, file_size + 1> file_string_ascii{};
        std::ranges::copy(
            header.file | std::views::transform(std::to_integer<char>),
            std::begin(file_string_ascii));
        std::ranges::for_each(file_string_ascii, json_pritify);
        file_string_ascii.back() = '\0';

        output = std::format_to(
            output,
            "{{"
            "\"op\":{}"
            ","
            "\"htype\":\"0x{:x}\""
            ","
            "\"hlen\":{}"
            ","
            "\"hops\":{}"
            ","
            "\"transaction_id\":\"0x{:x}\""
            ","
            "\"secs\":{}"
            ","
            "\"flags\":\"0b{}\""
            ","
            "\"cli\":{}"
            ","
            "\"your\":{}"
            ","
            "\"server\":{}"
            ","
            "\"relay\":{}"
            ","
            "\"cli_hw\":\"{}\""
            ","
            "\"sname_ascii\":\"{}\""
            ","
            "\"file_ascii\":\"{}\""
            "}}",
            header.op,
            header.htype,
            header.hlen,
            header.hops,
            header.xid,
            header.secs,
            std::bitset<16>(header.flags).to_string(),
            header.ciaddr,
            header.yiaddr,
            header.siaddr,
            header.giaddr,
            header.chaddr,
            sname_string_ascii.data(),
            file_string_ascii.data());
        return output;
    }

  private:
    template <typename T>
    struct std_array_size
    {
    };

    template <typename T, size_t S>
    struct std_array_size<std::array<T, S>>
    {
        static constexpr size_t value = S;
    };

    template <typename T>
    static constexpr size_t std_array_size_v = std_array_size<T>::value;
};
