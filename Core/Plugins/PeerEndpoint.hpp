#pragma once

#include <cstdint>
#include <array>
#include <string>

#include "Core/Plugins/Vip.hpp"

// Simple endpoint abstraction decoupled from ASIO types.
struct PeerEndpoint
{
    bool                        v6 {false};
    std::array<std::uint8_t,16> addr{};
    std::uint16_t               port {0};

    static PeerEndpoint FromIPv4(std::uint32_t host_order, std::uint16_t port_) noexcept
    {
        PeerEndpoint e;
        e.v6   = false;
        e.port = port_;
        e.addr[0] = static_cast<std::uint8_t>((host_order >> 24) & 0xFF);
        e.addr[1] = static_cast<std::uint8_t>((host_order >> 16) & 0xFF);
        e.addr[2] = static_cast<std::uint8_t>((host_order >>  8) & 0xFF);
        e.addr[3] = static_cast<std::uint8_t>((host_order      ) & 0xFF);
        return e;
    }

    static PeerEndpoint FromIPv6(const std::array<std::uint8_t,16> &a, std::uint16_t port_) noexcept
    {
        PeerEndpoint e;
        e.v6   = true;
        e.port = port_;
        e.addr = a;
        return e;
    }

    static PeerEndpoint FromVipAndPort(const VipKey &vip, std::uint16_t port_) noexcept
    {
        return vip.v6 ? FromIPv6(vip.v6addr, port_) : FromIPv4(vip.v4, port_);
    }
};
