#pragma once

#include <bitset>
#include <format>
#include <string>

#include <cstddef>
#include <cstdint>

#include <xnet/IPv4.hh>

template <>
struct std::formatter<xnet::IPv4::Address, char>
{
    template <class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext &ctx)
    {
        return ctx.begin();
    }

    template <typename FmtContext>
    auto format(const xnet::IPv4::Address &addr, FmtContext &ctx) const
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
struct std::formatter<xnet::IPv4::Header, char>
{
    template <class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext &ctx)
    {
        return ctx.begin();
    }

    template <typename FmtContext>
    auto format(const xnet::IPv4::Header &H, FmtContext &ctx) const
    {
        auto output = ctx.out();

        std::string header_size_if_not_20;
        if (H.header_size != 20) {
            header_size_if_not_20 =
                std::format(",\"header_size\":{}", H.header_size);
        }

        std::string fragment_offset_if_not_zero;
        if (H.fragment_offset != 0) {
            fragment_offset_if_not_zero =
                std::format(",\"fragment_offset\":{}", H.fragment_offset);
        }

        std::string type_of_service_if_not_zero;
        if (H.type_of_service != 0) {
            type_of_service_if_not_zero = std::format(
                ",\"TOS_bits\":\"{}\"",
                std::bitset<8>(H.type_of_service).to_string());
        }

        return std::format_to(
            output,
            "{{"
            "\"src_str\":\"{}\""
            ",\"dst_str\":\"{}\""
            ",\"size\":{}"
            ",\"TTL\":{}"
            ",\"proto\":{}"
            ",\"id\":{}"
            ",\"flags_bits\":\"{}\""
            ",\"checksum\":{}"
            "{}" // fragment_offset_if_not_zero
            "{}" // type_of_service_if_not_zero
            "{}" // header_size_if_not_20
            "}}",
            H.source_address,
            H.destination_address,
            H.total_size,
            H.time_to_live,
            H.protocol,
            H.identification,
            std::bitset<3>(H.flags).to_string(),
            H.checksum,
            fragment_offset_if_not_zero,
            type_of_service_if_not_zero,
            header_size_if_not_20);
    }
};
