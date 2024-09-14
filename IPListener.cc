#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
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
#include <thread>
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

#include <xnet/IPv4.hh>
#include <xnet/IPv4_formatter.hh>
#include <xnet/DHCP.hh>
#include <xnet/DHCP_formatter.hh>
#include <xnet/UDP.hh>

#include "IPInputInterface.hh"

#include <ctime>

std::atomic<bool> should_close = false;
void sighandler(int /*signo*/)
{
    should_close = true;
}

size_t last_sample_time = 0;

size_t counter = 0;
size_t last_sampled_counter = 0;

size_t last_second_packets = 0;

size_t last_string_output_size = 0;

size_t last_speed = 0;

int main(int argc, char **argv)
try {
    signal(SIGINT, sighandler);

    IPInputInterface ip_source;

    while (!should_close) {

        ip_source.process();
		size_t new_sample_time = time(nullptr);
		size_t time_diff = new_sample_time - last_sample_time;
		if (time_diff > 0) {
			last_speed = counter - last_second_packets;
			last_second_packets = counter;
			last_sample_time = new_sample_time;
		}
		std::string output = std::format("kbytes: {} | kbyte/s {}", counter, last_speed);
		std::cout << '\r';
		std::string pad;
		if (output.size() < last_string_output_size){
		    pad.resize(last_string_output_size - output.size());
		}
		std::fill(begin(pad),end(pad), ' ');
		std::cout << '\r';
		std::cout << output << pad;

		last_string_output_size = output.size();
            std::cout.flush();

        std::optional<xnet::IPv4::PacketView> packet = ip_source.active_packet();
        if (!packet) {
            continue;
        }
        struct PopPacketRAII
        {
            PopPacketRAII(std::reference_wrapper<IPInputInterface> s) : m_src(s)
            {
            }
            ~PopPacketRAII()
            {
                m_src.get().pop();
            }

          private:
            std::reference_wrapper<IPInputInterface> m_src;
        } pop_g(std::ref(ip_source));

        auto packet_header_view = packet->header_view();

        auto ip_header = packet_header_view.parse();

        if (ip_header.has_value()) {
		counter += ip_header->total_size / 1024;
            //std::cout << std::format("{}\n", ip_header.value());
        }
    }

} catch (std::exception &e) {
    std::cout << std::format("Error: {}\n", e.what());
}
