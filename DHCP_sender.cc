#include <algorithm>
#include <array>
#include <format>
#include <iostream>
#include <iterator>
#include <ranges>
#include <stdexcept>
#include <string>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <unistd.h>

#include "DHCP.hh"
#include "IPv4.hh"

struct DHCPSink
{
    DHCPSink()
    {
        auto fd_socket = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd_socket < 0) {
            auto status = errno;
            throw std::runtime_error(
                std::format("DHCPSink create failue: {}", strerror(status)));
        }

        int true_num = 1;
        if (0 !=
            setsockopt(
                fd_socket,
                SOL_SOCKET,
                SO_BROADCAST,
                &true_num,
                sizeof(true_num))) {
            auto status = errno;
            close(fd_socket);
            throw std::runtime_error(std::format(
                "DHCPSink broadcast enable failue: {}", strerror(status)));
        }

        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(67);

        if (::bind(
                fd_socket,
                reinterpret_cast<sockaddr *>(&addr),
                sizeof(sockaddr_in)) != 0) {
            auto status = errno;
            close(fd_socket);
            throw std::runtime_error(
                std::format("DHCPSink bind port failue: {}", strerror(status)));
        };

        fd = fd_socket;
    }

    ~DHCPSink()
    {
        close(fd);
    }

    bool send_header(const dhcp::Header h)
    {
        auto data = dhcp::serialize(h);

        std::array<uint8_t, 5> options{0x63, 0x82, 0x53, 0x63, 0xff};

        std::ranges::copy(
            options |
                std::views::transform([](auto a) { return std::byte(a); }),
            std::back_inserter(data));

        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_BROADCAST;
        addr.sin_port = 0;

        std::memcpy(
            &addr.sin_port, dhcp::htobe<uint16_t>(68).data(), sizeof(uint16_t));

        auto written = sendto(
            fd,
            data.data(),
            data.size(),
            0,
            reinterpret_cast<sockaddr *>(&addr),
            sizeof(addr));

        if (written < 0) {
            std::cout << std::format(
                "DHCPSink::send_header failue: {}", strerror(errno));
            return false;
        }

        return true;
    }

  private:
    int fd = -1;
};

int main()
try {
    dhcp::Header header;
    header.op = dhcp::OperationCode::BOOTREPLY;
    header.hlen = 6;
    header.htype = 1;
    header.chaddr =
        dhcp::ClientHardwareAddr({0x00, 0x23, 0x5a, 0xcd, 0x09, 0xb0});
    header.flags = 0b1000000000000000;
    header.xid = 0x5bcd09b0;
    header.secs = 48;

    std::string file_name;
    file_name.resize(128);
    std::ranges::fill(file_name, '-');

    for (size_t s = 120; s < 128; s++) {
        file_name[s] = '0' + s % 10;
    }

    std::memcpy(
        header.file.data(),
        file_name.data(),
        std::min(file_name.size(), header.file.size()));
    header.file.back() = 0;
    header.yiaddr = IPv4::Address::from_msbf(0377);

    DHCPSink s;

    s.send_header(header);
} catch (std::exception &e) {
    std::cout << std::format("Error: {}\n", e.what());
}
