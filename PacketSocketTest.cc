#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <ranges>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/socket.h>

int main()
{
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (s < 0) {
        auto status = errno;
        std::cout << strerror(status);
        return EXIT_FAILURE;
    }

    std::byte data[1024];
    std::ranges::fill(data, std::byte(0));

    sockaddr_ll addr;
    addr.sll_family = AF_INET;
    addr.sll_halen = 8;
    addr.sll_ifindex = 2;
    for (size_t s = 0; s < sizeof(addr.sll_addr); s++) {
        addr.sll_addr[s] = s;
    }
    sockaddr *addr_p = reinterpret_cast<sockaddr *>(&addr);
    socklen_t addr_size = sizeof(addr);
    // auto recvd = recvfrom(s, data, sizeof(data), 0, addr_p, &addr_size);
    auto sended = sendto(s, data, sizeof(data), 0, addr_p, addr_size);
}
