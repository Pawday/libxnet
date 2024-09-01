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

#include "IPSource.hh"
#include "IPv4.hh"

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

struct IPSource::Impl
{
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

    Impl()
    {
        int new_epoll_fd = ::epoll_create(1);
        if (new_epoll_fd < 0) {
            auto status = errno;
            throw std::runtime_error(std::format(
                "Creation epoll for socket error: {}", strerror(status)));
        }
        fd.epoll = new_epoll_fd;

        int new_socket = ::socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
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

            std::ranges::copy(
                readen_span, std::back_inserter(m_raw_ip_packets));
        }
    }

    void parse_ip_packets()
    {
        auto packets_span = std::span(m_raw_ip_packets);
        if (packets_span.size() == 0) {
            return;
        }

        size_t parsed = 0;

        while (true) {
            if (packets_span.size() < parsed) {
                break;
            }
            packets_span = packets_span.subspan(parsed);

            IPv4::PacketView packet(packets_span);
            if (packet.is_not_valid()) {
                break;
            }

            auto packet_size = packet.total_size();
            if (!packet_size) {
                break;
            }

            std::vector<std::byte> request;
            std::ranges::copy(
                packets_span | std::views::take(packet_size.value()),
                std::back_inserter(request));
            parsed += packet_size.value();

            m_packets.push_back(std::move(request));
        }

        if (parsed == 0) {
            m_error_status = "Invalid ip packet sequence found";
            throw_active_status();
        }

        m_raw_ip_packets.erase(
            begin(m_raw_ip_packets), begin(m_raw_ip_packets) + parsed);
    }

    Descriptors fd;

    std::vector<std::byte> m_raw_ip_packets;
    std::deque<std::vector<std::byte>> m_packets;

    std::optional<std::string> m_error_status = std::nullopt;
    std::vector<std::byte> m_data;
};

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
