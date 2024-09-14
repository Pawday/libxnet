#pragma once

#include <algorithm>
#include <array>
#include <bitset>
#include <format>
#include <iterator>
#include <string>

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "DHCP.hh"

template <>
struct std::formatter<dhcp::OperationCode, char>
{
    template <class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext &ctx)
    {
        return ctx.begin();
    }

    template <typename FmtContext>
    constexpr auto
        format(const dhcp::OperationCode &code, FmtContext &ctx) const
    {
        auto output = ctx.out();

        switch (code) {
            using enum dhcp::OperationCode;
        case BOOTREQUEST:
            return std::format_to(output, "BOOTREQUEST");
        case BOOTREPLY:
            return std::format_to(output, "BOOTREPLY");
        }

        throw std::format_error("Unknown dhcp opcode");
    }
};

template <>
struct std::formatter<dhcp::ClientHardwareAddr, char>
{
    template <class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext &ctx)
    {
        return ctx.begin();
    }

    template <typename FmtContext>
    auto format(const dhcp::ClientHardwareAddr &addr, FmtContext &ctx) const
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
struct std::formatter<dhcp::Header, char>
{
    template <class ParseContext>
    constexpr ParseContext::iterator parse(ParseContext &ctx)
    {
        return ctx.begin();
    }

    template <typename FmtContext>
    auto format(const dhcp::Header /* not & */ header, FmtContext &ctx) const
    {
        auto output = ctx.out();

        constexpr size_t sname_data_size =
            std_array_size_v<decltype(dhcp::Header::sname)>;
        constexpr size_t file_data_size =
            std_array_size_v<decltype(dhcp::Header::file)>;

        constexpr size_t sname_data_string_size =
            sname_data_size * (sizeof("xx") - 1) /* each byte as string */
            + sname_data_size - 1                /* comma between */
            + 1 /* zero term */;

        constexpr size_t file_data_string_size =
            file_data_size * (sizeof("xx") - 1) /* each byte as string */
            + file_data_size - 1                /* comma between */
            + 1 /* zero term */;

        std::array<char, sname_data_string_size> sname_arr_stringify{};
        std::array<char, file_data_string_size> file_arr_stringify{};

        auto sname_string_it = std::begin(sname_arr_stringify);

        bool first = true;
        for (auto sname_byte : header.sname) {
            if (!first) {
                sname_string_it = std::format_to(sname_string_it, " ");
            }
            first = false;
            sname_string_it =
                std::format_to(sname_string_it, "{:02x}", sname_byte);
        }

        auto file_string_it = std::begin(file_arr_stringify);
        first = true;
        for (auto file_name_byte : header.file) {
            if (!first) {
                file_string_it = std::format_to(sname_string_it, " ");
            }
            first = false;
            sname_string_it =
                std::format_to(file_string_it, "{:02x}", file_name_byte);
        }

        std::string sname_string_ascii = "";
        if (header.is_sname_valid()) {
            sname_string_ascii = header.sname_string();
        }

        auto json_pritify = [](char &c) {
            switch (c) {
            case '\"':
            case '\\':
                c = '.';
                return;
            }

            if (std::isprint(c)) {
                return;
            }
            c = '.';
        };

        std::ranges::for_each(sname_string_ascii, json_pritify);

        std::string file_string_ascii = "";
        if (header.is_file_valid()) {
            file_string_ascii = header.file_string();
        }
        std::ranges::for_each(file_string_ascii, json_pritify);

        output = std::format_to(
            output,
            "{{"
            "\"op\":\"{}\""
            ","
            "\"htype\":\"0x{:x}\""
            ","
            "\"hlen\":{}"
            ","
            "\"hops\":{}"
            ","
            "\"xid\":\"0x{:x}\""
            ","
            "\"secs\":{}"
            ","
            "\"flags\":\"0b{}\""
            ","
            "\"ciaddr\":\"{}\""
            ","
            "\"yiaddr\":\"{}\""
            ","
            "\"siaddr\":\"{}\""
            ","
            "\"giaddr\":\"{}\""
            ","
            "\"chaddr\":\"{}\""
            ","
            "\"sname_string_ascii\":\"{}\""
            ","
            "\"file_string_ascii\":\"{}\""
            ","
            "\"sname\":\"{}\""
            ","
            "\"file\":\"{}\""
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
            sname_string_ascii,
            file_string_ascii,
            sname_arr_stringify.data(),
            file_arr_stringify.data());
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
