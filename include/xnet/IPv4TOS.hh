#include <cstdint>

namespace xnet {
namespace IPv4 {

struct TypeOfService
{
    constexpr TypeOfService() : m_val(0)
    {
    }

    constexpr TypeOfService(uint8_t val) : m_val(val)
    {
    }

    bool normal_routine() const
    {
        return (m_val & 0b11111100) == 0;
    }

    constexpr uint8_t value() const
    {
        return m_val;
    }

    uint8_t precedence() const
    {
        return (m_val >> 5) & 0b00000111;
    }

    bool low_delay() const
    {
        return (m_val & 0b00010000) != 0;
    }

    bool normal_delay() const
    {
        return !low_delay();
    }

    bool high_throughput() const
    {
        return (m_val & 0b00001000) != 0;
    }

    bool normal_throughput() const
    {
        return !high_throughput();
    }

    bool high_relibility() const
    {
        return (m_val & 0b00000100) != 0;
    }

    bool normal_relibility() const
    {
        return !high_relibility();
    }

    bool any_reserved() const
    {
        return (m_val & 0b00000011) != 0;
    }

    bool reserved_6() const
    {
        return (m_val & 0b00000010) != 0;
    }

    bool reserved_7() const
    {
        return (m_val & 0b10000001) != 0;
    }

  private:
    uint8_t m_val;
};

} // namespace IPv4
} // namespace xnet
