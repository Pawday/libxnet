#include <cassert>
#include <cstddef>
#include <optional>
#include <stdexcept>
#include <utility>

#include "IPv4.hh"

#include "IPSource.hh"

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

    void process()
    {
        throw std::runtime_error("Not implemented");
    }

    std::optional<IPv4::PacketView> active_packet() const
    {
        return std::nullopt;
    }

    void pop()
    {
        throw std::runtime_error("Not implemented");
    }
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
