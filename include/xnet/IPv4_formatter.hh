#pragma once

#include <format>

#include <cstddef>
#include <cstdint>

#include <xnet/IPv4.hh>
#include <xnet/IPv4TOS.hh>

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
            "[{},{},{},{}]",
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

        output = std::format_to(output, "{{");

        output = std::format_to(
            output,
            "\"src\":{}"
            ",\"dst\":{}"
            ",\"size\":{}"
            ",\"TTL\":{}"
            ",\"proto\":{}"
            ",\"id\":{}",
            H.source_address,
            H.destination_address,
            H.total_size,
            H.time_to_live,
            H.protocol,
            H.identification);

        output = std::format_to(output, ",\"checksum\":{}", H.checksum);
        output = std::format_to(output, ",\"flags\":{}", H.flags);

        if (H.fragment_offset != 0) {
            output = std::format_to(
                output, ",\"fragment_offset\":{}", H.fragment_offset);
        }

        auto TOS = xnet::IPv4::TypeOfService(H.TOS_or_DS);

        if (!TOS.normal_routine() || TOS.any_reserved()) {
            output = std::format_to(output, ",\"TOS\":{}", TOS);
        }

        if (H.header_size != 20) {
            output =
                std::format_to(output, ",\"header_size\":{}", H.header_size);
        }

        output = std::format_to(output, "}}");

        return output;
    }
};

template <>
struct std::formatter<xnet::IPv4::Flags, char>
{
    template <class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext &ctx)
    {
        return ctx.begin();
    }

    template <typename FmtContext>
    auto format(const xnet::IPv4::Flags &F, FmtContext &ctx) const
    {
        auto output = ctx.out();

        output = std::format_to(output, "[");

        auto paste_separator_if = [&output](bool cond) {
            if (!cond) {
                return;
            }
            output = std::format_to(output, ",");
        };

        bool has_prev = false;

        if (F.dont_fragment()) {
            output = std::format_to(output, "\"DONTF\"");
        } else {
            output = std::format_to(output, "\"MAYF\"");
        }
        has_prev = true;

        if (F.more_fragments()) {
            paste_separator_if(has_prev);
            has_prev = true;
            output = std::format_to(output, "\"MORE\"");
        }

        if (F.reserved()) {
            paste_separator_if(has_prev);
            has_prev = true;
            output = std::format_to(output, "\"RSV\"");
        }

        output = std::format_to(output, "]");

        return output;
    }
};

template <>
struct std::formatter<xnet::IPv4::TypeOfService, char>
{
    template <class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext &ctx)
    {
        return ctx.begin();
    }

    template <typename FmtContext>
    auto format(const xnet::IPv4::TypeOfService &TOS, FmtContext &ctx) const
    {
        auto output = ctx.out();

        output = std::format_to(output, "{{");
        auto paste_separator_if = [&output](bool cond) {
            if (!cond) {
                return;
            }
            output = std::format_to(output, ",");
        };

        bool has_prev_obj = false;
        if (TOS.precedence() != 0) {
            paste_separator_if(has_prev_obj);
            has_prev_obj = true;
            output =
                std::format_to(output, "\"precedence\":{}", TOS.precedence());
        }

        if (TOS.low_delay() || TOS.high_throughput() || TOS.high_relibility()) {
            paste_separator_if(has_prev_obj);
            has_prev_obj = true;

            output = std::format_to(output, "[");

            bool has_prev_flag = false;

            if (TOS.low_delay()) {
                paste_separator_if(has_prev_flag);
                output = std::format_to(output, "\"NDELAY\"", TOS.low_delay());
                has_prev_flag = true;
            }

            if (TOS.high_throughput()) {
                paste_separator_if(has_prev_flag);
                output = std::format_to(output, "\"HTHROUT\"", TOS.low_delay());
                has_prev_flag = true;
            }

            if (TOS.high_relibility()) {
                paste_separator_if(has_prev_flag);
                output = std::format_to(output, "\"HRELY\"", TOS.low_delay());
                has_prev_flag = true;
            }

            output = std::format_to(output, "]");
        }

        if (TOS.any_reserved()) {
            paste_separator_if(has_prev_obj);
            has_prev_obj = true;
            output = std::format_to(
                output,
                "\"reserved_67\":[{},{}]",
                TOS.reserved_6(),
                TOS.reserved_7());
        }

        output = std::format_to(output, "}}");

        return output;
    }
};
