#include <algorithm>
#include <deque>
#include <format>
#include <iterator>
#include <optional>
#include <ranges>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <cstdint>
#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstring>

#include <fcntl.h>
#include <netinet/in.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if_ether.h>

#include <xnet/IPv4.hh>

#include "IPInputInterface.hh"

struct Descriptors
{
    Descriptors() = default;
    Descriptors(const Descriptors &) = delete;
    Descriptors(Descriptors &&o) : socket(o.socket), epoll(o.epoll)
    {
        o.socket = -1;
        o.epoll = -1;
        o.moved = true;
    }
    Descriptors &operator=(const Descriptors &) = delete;
    Descriptors &operator=(Descriptors &&o)
    {
        std::swap(*this, o);
        return *this;
    }

    ~Descriptors()
    {
        if (moved) {
            return;
        }
        close(epoll);
        close(socket);
    }

    bool moved = false;
    int epoll = -1;
    int socket = -1;
};

struct IPInputInterface::Impl
{
    static Impl &cast(IPInputInterface &s)
    {
        return *reinterpret_cast<Impl *>(s.impl);
    }

    static Impl const &cast(const IPInputInterface &s)
    {
        return *reinterpret_cast<const Impl *>(s.impl);
    }

    static void assert_impl()
    {
        static_assert(alignof(Impl) <= alignof(IPInputInterface));
        static_assert(sizeof(Impl) <= sizeof(IPInputInterface));
    }

    Impl()
    {
        int new_epoll_fd = ::epoll_create(1);
        if (new_epoll_fd < 0) {
            auto status = errno;
            throw std::runtime_error(std::format(
                "Creation epoll for socket error: {}", strerror(status)));
        }
        fd.epoll = new_epoll_fd;

        int new_socket = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (new_socket < 0) {
            auto status = errno;
            close(new_epoll_fd);
            throw std::runtime_error(
                std::format("Socket error: {}", strerror(status)));
        }

        struct epoll_event ev;
        ev.data.fd = new_socket;
        ev.events = EPOLLIN;
        int epl_add_status =
            ::epoll_ctl(fd.epoll, EPOLL_CTL_ADD, new_socket, &ev);
        if (0 != epl_add_status) {
            auto status = errno;
            close(new_epoll_fd);
            close(new_socket);
            throw std::runtime_error(
                std::format("Socket epoll bind failue: {}", strerror(status)));
        }

        int flags = fcntl(new_socket, F_GETFL);
        if (-1 == flags) {
            auto status = errno;
            close(new_epoll_fd);
            close(new_socket);
            throw std::runtime_error(
                std::format("Socket get flags failue: {}", strerror(status)));
        }
        flags |= O_NONBLOCK;
        if (0 != fcntl(new_socket, F_SETFL, flags)) {
            auto status = errno;
            close(new_epoll_fd);
            close(new_socket);
            throw std::runtime_error(std::format(
                "Socket append nonblock flag failue: {}", strerror(status)));
        }
        fd.socket = new_socket;
    }

    void process()
    {
        check_valid_or_throw();
        read_raw_packets();
        parse_ip_packets();
    }

    std::optional<xnet::IPv4::PacketView> active_packet() const
    {
        if (m_raw_packets.size() == 0) {
            return std::nullopt;
        }
        const std::vector<std::byte> &packet_data = m_raw_packets.front();
        auto data_as_span = std::span(packet_data.data(), packet_data.size());
        return xnet::IPv4::PacketView(data_as_span);
    }

    void pop()
    {
        assert(m_raw_packets.size() != 0);
        m_raw_packets.pop_front();
    }

  private:
    void throw_active_status()
    {
        if (!m_error_status) {
            return;
        }
        throw std::runtime_error(std::format(
            "Socket {} is invalid: status {}",
            fd.socket,
            m_error_status.value()));
    }

    void check_valid_or_throw()
    {
        throw_active_status();

        if (fd.moved) {
            m_error_status = "moved descriptors";
            throw_active_status();
        }
    }

    void read_raw_packets()
    {
        constexpr size_t max_events = 16;
        epoll_event events[max_events];
        int nb_events = epoll_wait(fd.epoll, events, max_events, 0);
        if (nb_events > max_events) {
            throw std::runtime_error("Linux epoll_wait fucked: epoll_wait() "
                                     "output is greater then its 3rd arg");
            throw_active_status();
        }

        if (nb_events == 0) {
            return;
        }

        for (size_t event_idx = 0; event_idx < nb_events; event_idx++) {
            epoll_event &event = events[event_idx];
            if (event.data.fd != fd.socket) {
                m_error_status = "Unexpected socket descriptor from epoll_wait";
                throw_active_status();
            }

            int to_read = recvfrom(
                fd.socket, nullptr, 0, MSG_TRUNC | MSG_PEEK, NULL, NULL);
            int status = errno;
            if (status == EAGAIN) {
                return;
            }

            std::vector<std::byte> recv_buff;
            recv_buff.resize(to_read);

            int readen = recvfrom(
                fd.socket, recv_buff.data(), recv_buff.size(), 0, NULL, NULL);

            status = errno;

            if (readen > to_read) {
                m_error_status =
                    "Unexpected socket read size change after size request"
                    "(MSG_TRUNC | MSG_PEEK) and recv call";
                throw_active_status();
            }

            if (status == EAGAIN) {
                return;
            }

            if (readen < 0) {
                m_error_status = "Read error occured";
                throw_active_status();
            }

            auto readen_span = recv_buff | std::views::take(readen);

            std::ranges::copy(readen_span, std::back_inserter(m_capture));
        }
    }

    void parse_ip_packets()
    {
        auto packets_span = std::span(m_capture);
        if (packets_span.size() == 0) {
            return;
        }

        auto is_ipv4_start = [](std::byte b) {
            uint8_t version = std::to_integer<uint8_t>(b);
            return (version & 0xf0) == 0x40;
        };

        size_t packet_offset = 0;

        // Search first valid IPv4 packet
        while (true) {
            if (packet_offset > packets_span.size()) {
                return;
            }

            auto ipv4_start = std::find_if(
                begin(packets_span) + packet_offset,
                end(packets_span),
                is_ipv4_start);

            if (ipv4_start == std::end(packets_span)) {
                return;
            }

            packet_offset = std::distance(begin(packets_span), ipv4_start);

            xnet::IPv4::PacketView packet(packets_span.subspan(packet_offset));
            if (packet.is_valid()) {
                break;
            }
            packet_offset++;
        }

        m_capture.erase(begin(m_capture), begin(m_capture) + packet_offset);
        packets_span = std::span(m_capture);
        packet_offset = 0;

        // Try to iterate IPv4 packets sequentially
        // do not search nested IPv4 packets
        while (true) {
            if (packet_offset > packets_span.size()) {
                break;
            }

            xnet::IPv4::PacketView packet(packets_span);
            if (packet.is_not_valid()) {
                break;
            }

            auto packet_size_opt = packet.header_view().total_size();
            auto packet_raw_data_opt = packet.clone_data();
            if (!packet_raw_data_opt.has_value() ||
                !packet_size_opt.has_value()) {
                break;
            }

            if (packet_size_opt.value() + packet_offset > packets_span.size()) {
                break;
            }

            auto packet_data = packet_raw_data_opt.value();
            assert(packet_data.size() == packet_size_opt.value());
            m_raw_packets.emplace_back(std::move(packet_data));

            packet_offset += packet_size_opt.value();
        }

        m_capture.erase(begin(m_capture), begin(m_capture) + packet_offset);
    }

    Descriptors fd;

    std::vector<std::byte> m_capture;
    std::deque<std::vector<std::byte>> m_raw_packets;

    std::optional<std::string> m_error_status = std::nullopt;
    std::vector<std::byte> m_data;
};

void IPInputInterface::process()
{
    Impl::cast(*this).process();
}

std::optional<xnet::IPv4::PacketView> IPInputInterface::active_packet() const
{
    return Impl::cast(*this).active_packet();
}

void IPInputInterface::pop()
{
    return Impl::cast(*this).pop();
}

IPInputInterface::IPInputInterface()
{
    new (impl) IPInputInterface::Impl();
}

IPInputInterface::IPInputInterface(IPInputInterface &&o)
{
    new (impl) IPInputInterface::Impl(std::move(Impl::cast(o)));
}

IPInputInterface &IPInputInterface::operator=(IPInputInterface &&o)
{
    Impl::cast(*this).operator=(std::move(Impl::cast(o)));
    return *this;
}

IPInputInterface::~IPInputInterface()
{
    Impl::cast(*this).~Impl();
}
