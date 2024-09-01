#pragma once

#include <array>
#include <optional>
#include <span>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>

struct UDPHeader
{
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksumm;
};

struct UDPPacketView
{
    UDPPacketView(std::span<const std::byte> data) : m_data(data)
    {
    }

    std::optional<UDPHeader> header() const
    {
        if (m_data.size() < udp_header_size) {
            return std::nullopt;
        }

        std::array<uint16_t, 4> readen_u16s{};
        for (uint8_t u16_idx = 0; u16_idx < udp_header_size / sizeof(uint16_t);
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

        UDPHeader output;
        output.source_port = readen_u16s[0];
        output.destination_port = readen_u16s[1];
        output.length = readen_u16s[2];
        output.checksumm = readen_u16s[3];
        return output;
    }

    std::optional<std::span<const std::byte>> payload() const
    {
        auto header_opt = header();
        if (!header_opt) {
            return std::nullopt;
        }

        auto udp_header = header_opt.value();
        if (udp_header.length < udp_header_size) {
            assert(false && "UDPPacketView::header().length screwed");
            return std::nullopt;
        }

        uint16_t payload_len = udp_header.length - udp_header_size;

        if (m_data.size() < udp_header_size) {
            assert(
                false &&
                "Unexpected m_data span size change after reading header");
            return std::nullopt;
        }

        if ((m_data.size() - udp_header_size) < payload_len) {
            return std::nullopt;
        }

        return m_data.subspan(udp_header_size, payload_len);
    }

  private:
    static constexpr uint8_t udp_header_size = 8;

    std::span<const std::byte> m_data;
};
