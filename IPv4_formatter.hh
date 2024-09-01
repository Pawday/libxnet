#pragma once

#include <bitset>
#include <cstddef>
#include <cstdint>
#include <format>

#include "IPv4.hh"

template <>
struct std::formatter<IPv4::Address, char>
{
    template <class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext &ctx)
    {
        return ctx.begin();
    }

    template <typename FmtContext>
    auto format(const IPv4::Address &addr, FmtContext &ctx) const
    {
        auto output = ctx.out();

        auto m_data = addr.data_msbf();

        auto num = [](std::byte b) { return std::to_integer<uint16_t>(b); };
        output = std::format_to(
            output,
            "{}.{}.{}.{}",
            num(m_data[0]),
            num(m_data[1]),
            num(m_data[2]),
            num(m_data[3]));
        return output;
    }
};

template <>
struct std::formatter<IPv4::Header, char>
{
    template <class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext &ctx)
    {
        return ctx.begin();
    }

    template <typename FmtContext>
    auto format(const IPv4::Header &addr, FmtContext &ctx) const
    {
        auto output = ctx.out();

        return std::format_to(
            output,
            "{{"
            "\"header_size\":{}"
            ","
            "\"type_of_service\":{}"
            ","
            "\"total_length\":{}"
            ","
            "\"identification\":{}"
            ","
            "\"flags_string\":\"0b{}\""
            ","
            "\"fragment_offset\":{}"
            ","
            "\"time_to_live\":{}"
            ","
            "\"protocol\":{}"
            ","
            "\"header_checksum\":{}"
            ","
            "\"source_address_string\":\"{}\""
            ","
            "\"destination_address_string\":\"{}\""
            "}}",
            addr.header_size,
            addr.type_of_service,
            addr.total_size,
            addr.identification,
            std::bitset<3>(addr.flags).to_string(),
            addr.fragment_offset,
            addr.time_to_live,
            addr.protocol,
            addr.checksum,
            addr.source_address,
            addr.destination_address
         );
    }
};
