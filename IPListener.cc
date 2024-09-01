#include <algorithm>
#include <array>
#include <atomic>
#include <deque>
#include <endian.h>
#include <exception>
#include <format>
#include <functional>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <ranges>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <cassert>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <cstring>

#include <fcntl.h>
#include <netinet/in.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "IPv4.hh"
#include "IPv4_formatter.hh"

#include "DHCP.hh"
#include "DHCP_formatter.hh"

#include "IPSource.hh"
#include "UDP.hh"

std::atomic<bool> should_close = false;
void sighandler(int /*signo*/)
{
    should_close = true;
}

int main(int argc, char **argv)
try {
    signal(SIGINT, sighandler);

    IPSource ip_source;

    while (!should_close) {

        ip_source.process();

        std::optional<IPv4::PacketView> packet = ip_source.active_packet();
        if (!packet) {
            continue;
        }
        struct PopPacketRAII
        {
            PopPacketRAII(std::reference_wrapper<IPSource> s) : m_src(s)
            {
            }
            ~PopPacketRAII()
            {
                m_src.get().pop();
            }

          private:
            std::reference_wrapper<IPSource> m_src;
        } pop_g(std::ref(ip_source));

        auto ip_header = packet->parse_header();

        if (ip_header.has_value()) {
            std::cout << std::format("{}\n", ip_header.value());
            std::cout.flush();
        }
    }

} catch (std::exception &e) {
    std::cout << std::format("Error: {}\n", e.what());
}
