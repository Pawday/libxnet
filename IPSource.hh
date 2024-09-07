#pragma once

#include <optional>

#include "IPv4.hh"

struct IPInputInterface
{
    void process();
    std::optional<IPv4::PacketView> active_packet() const;
    void pop();

    IPInputInterface();
    IPInputInterface(IPInputInterface const &) = delete;
    IPInputInterface(IPInputInterface &&);
    IPInputInterface &operator=(IPInputInterface const &) = delete;
    IPInputInterface &operator=(IPInputInterface &&);
    ~IPInputInterface();

  private:
    struct Impl;
    alignas(8) char impl[256];
};
