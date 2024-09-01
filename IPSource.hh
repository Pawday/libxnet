#pragma once

#include <optional>

#include "IPv4.hh"

struct IPSource
{
    void process();
    std::optional<IPv4::PacketView> active_packet() const;
    void pop();

    IPSource();
    IPSource(IPSource const &) = delete;
    IPSource(IPSource &&);
    IPSource &operator=(IPSource const &) = delete;
    IPSource &operator=(IPSource &&);
    ~IPSource();

  private:
    struct Impl;
    alignas(8) char impl[256];
};
