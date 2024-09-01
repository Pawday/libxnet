#include <algorithm>
#include <array>
#include <deque>
#include <format>
#include <iostream>
#include <iterator>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

#include <cassert>
#include <cstddef>
#include <cstdint>

#include <pcap/pcap.h>

#include "IPv4.hh"

#include "IPSource.hh"

namespace {
std::vector<IPv4::PacketView> search_packets(std::span<const std::byte> data)
{
    std::vector<size_t> ipv4_potential_offsets;

    auto start = std::begin(data);
    auto next = start;

    do {
        auto is_ipv4_start = [](std::byte b) {
            uint8_t version = std::to_integer<uint8_t>(b);
            return (version & 0xf0) == 0x40;
        };
        next = std::find_if(next, std::end(data), is_ipv4_start);
        if (next == std::end(data)) {
            break;
        }

        size_t offset = std::distance(start, next);
        next++;
        ipv4_potential_offsets.emplace_back(offset);
    } while (std::end(data) != next);

    std::vector<IPv4::PacketView> output;

    for (auto offset : ipv4_potential_offsets) {
        std::span<const std::byte> offset_data = data.subspan(offset);
        IPv4::PacketView packet(offset_data);

        if (packet.is_not_valid()) {
            continue;
        }

        output.emplace_back(packet);
    }

    return output;
}
} // namespace

struct IPSource::Impl
{
    static bool pcap_init_flag;

    static bool lazy_pcap_init()
    {
        if (pcap_init_flag) {
            return true;
        }

        static char pcap_error_buffer[PCAP_ERRBUF_SIZE];
        std::ranges::fill(pcap_error_buffer, 0);
        int init_status = pcap_init(PCAP_CHAR_ENC_UTF_8, pcap_error_buffer);
        if (init_status == PCAP_ERROR) {
            throw std::runtime_error(
                std::format("pcap_init failue: {}", pcap_error_buffer));
        }

        pcap_init_flag = true;
        return true;
    }

    static Impl &cast(IPSource &s)
    {
        return *reinterpret_cast<Impl *>(s.impl);
    }

    static Impl const &cast(const IPSource &s)
    {
        return *reinterpret_cast<const Impl *>(s.impl);
    }

    static void assert_impl()
    {
        static_assert(alignof(Impl) <= alignof(IPSource));
        static_assert(sizeof(Impl) <= sizeof(IPSource));
    }

    Impl(const Impl &) = delete;
    Impl(Impl &&o) : m_pcap(o.m_pcap)
    {
        o.m_pcap = nullptr;
    }

    Impl &operator=(Impl &&o)
    {
        std::swap(*this, o);
        return *this;
    }

    Impl()
    {
        lazy_pcap_init();

        std::array<char, PCAP_ERRBUF_SIZE> pcap_errbuff;
        pcap_t *new_pcap_handle = pcap_create(nullptr, pcap_errbuff.data());

        if (new_pcap_handle == nullptr) {
            throw std::runtime_error(
                std::format("pcap_create failue: {}", pcap_errbuff.data()));
        }

        auto set_imm_mod_status = pcap_set_immediate_mode(new_pcap_handle, 1);
        if (set_imm_mod_status != 0) {
            pcap_close(new_pcap_handle);
            throw std::runtime_error(std::format(
                "pcap_activate failue: {}",
                pcap_statustostr(set_imm_mod_status)));
        }

        auto activate_status = pcap_activate(new_pcap_handle);
        if (activate_status < 0) {
            pcap_close(new_pcap_handle);
            throw std::runtime_error(std::format(
                "pcap_activate failue: {}", pcap_statustostr(activate_status)));
        }

        auto set_nonblock_status =
            pcap_setnonblock(new_pcap_handle, 1, pcap_errbuff.data());
        if (set_nonblock_status != 0) {
            pcap_close(new_pcap_handle);
            throw std::runtime_error(std::format(
                "pcap_setnonblock(1) failue: {}", pcap_errbuff.data()));
        }

        m_pcap = new_pcap_handle;
    }

    ~Impl()
    {
        if (m_pcap == nullptr) {
            return;
        }
        pcap_close(m_pcap);
    }

    static void pcap_callback(
        uint8_t *user, const struct pcap_pkthdr *h, const uint8_t *bytes)
    {
        Impl *impl = reinterpret_cast<Impl *>(user);

        auto packets = search_packets(std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(bytes), h->caplen));

        for (auto &packet : packets) {
            impl->append_ip_packet(packet);
        }
    }

    void process()
    {
        auto dispatched_packets = pcap_dispatch(
            m_pcap, 0, pcap_callback, reinterpret_cast<uint8_t *>(this));

        if (dispatched_packets == 0) {
            return;
        }

        if (dispatched_packets < 0) {
            auto dispatch_failure_status = dispatched_packets;
            std::cout << std::format(
                "pcap process failue \"{}\"\n",
                pcap_statustostr(dispatch_failure_status));
        }
    }

    std::optional<IPv4::PacketView> active_packet() const
    {
        if (m_packets.size() == 0) {
            return std::nullopt;
        }
        const std::vector<std::byte> &packet_data = m_packets.front();
        auto data_as_span = std::span(packet_data.data(), packet_data.size());
        return IPv4::PacketView(data_as_span);
    }

    void pop()
    {
        assert(m_packets.size() != 0);
        m_packets.pop_front();
    }

  private:
    void append_ip_packet(IPv4::PacketView packet)
    {
        auto packet_data = packet.clone_data();
        if (!packet_data.has_value()) {
            return;
        }
        m_packets.emplace_back(std::move(packet_data.value()));
    }

    std::deque<std::vector<std::byte>> m_packets;
    pcap_t *m_pcap = nullptr;
};

bool IPSource::Impl::pcap_init_flag = false;

void IPSource::process()
{
    Impl::cast(*this).process();
}

std::optional<IPv4::PacketView> IPSource::active_packet() const
{
    return Impl::cast(*this).active_packet();
}

void IPSource::pop()
{
    return Impl::cast(*this).pop();
}

IPSource::IPSource()
{
    new (impl) IPSource::Impl();
}

IPSource::IPSource(IPSource &&o)
{
    new (impl) IPSource::Impl(std::move(Impl::cast(o)));
}

IPSource &IPSource::operator=(IPSource &&o)
{
    Impl::cast(*this).operator=(std::move(Impl::cast(o)));
    return *this;
}

IPSource::~IPSource()
{
    Impl::cast(*this).~Impl();
}
