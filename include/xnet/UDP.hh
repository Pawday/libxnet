#pragma once

#include <array>
#include <optional>
#include <span>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace xnet {

namespace UDP {

static constexpr uint8_t header_size = 8;

struct Header
{
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksumm;
};

struct PacketView
{
    PacketView(std::span<const std::byte> data) : m_data(data)
    {
    }

    std::optional<Header> parse_header() const
    {
        if (m_data.size() < header_size) {
            return std::nullopt;
        }

        std::array<uint16_t, 4> readen_u16s{};
        for (uint8_t u16_idx = 0; u16_idx < header_size / sizeof(uint16_t);
             u16_idx++) {
            auto val_be =
                m_data.subspan(u16_idx * sizeof(uint16_t), sizeof(uint16_t));

            uint16_t val = 0;
            val |= std::to_integer<uint8_t>(val_be[0]);
            val <<= 8;
            val &= 0xff00;
            val |= std::to_integer<uint8_t>(val_be[1]);
            readen_u16s[u16_idx] = val;
        }

        auto size = readen_u16s[2];
        if (size < header_size) {
            return std::nullopt;
        }

        Header output;
        output.source_port = readen_u16s[0];
        output.destination_port = readen_u16s[1];
        output.length = size;
        output.checksumm = readen_u16s[3];
        return output;
    }

    std::optional<std::span<const std::byte>> payload() const
    {
        auto header_opt = parse_header();
        if (!header_opt) {
            return std::nullopt;
        }

        auto udp_header = header_opt.value();
        if (udp_header.length < header_size) {
            assert(false && "parse_header screwed");
            return std::nullopt;
        }

        uint16_t payload_len = udp_header.length - header_size;

        if ((m_data.size() - header_size) < payload_len) {
            return std::nullopt;
        }

        return m_data.subspan(header_size, payload_len);
    }

  private:
    std::span<const std::byte> m_data;
};
} // namespace UDP
} // namespace xnet
