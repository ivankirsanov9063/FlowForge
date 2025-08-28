#pragma once

#include <cstdint>
#include <cstddef>
#include <array>
#include <functional>

// Public key used to shard/route traffic per virtual IP (IPv4/IPv6).
struct VipKey
{
    bool                         v6 = false;
    std::uint32_t                v4 = 0;                       // host order
    std::array<std::uint8_t,16>  v6addr{};                     // raw 16 bytes

    static VipKey FromV4(std::uint32_t host_order_addr) noexcept
    {
        VipKey k;
        k.v6 = false;
        k.v4 = host_order_addr;
        return k;
    }

    static VipKey FromV6(const std::array<std::uint8_t,16> &addr) noexcept
    {
        VipKey k;
        k.v6 = true;
        k.v6addr = addr;
        return k;
    }

    bool operator==(const VipKey &o) const noexcept
    {
        if (v6 != o.v6) return false;
        return v6 ? (v6addr == o.v6addr) : (v4 == o.v4);
    }

    struct Hasher
    {
        std::size_t operator()(const VipKey &k) const noexcept
        {
            if (!k.v6) return std::hash<std::uint32_t>{}(k.v4);
            // 64-bit FNV-1a over 16 bytes
            std::size_t h = 1469598103934665603ull;
            for (auto b : k.v6addr)
            {
                h ^= static_cast<std::size_t>(b);
                h *= 1099511628211ull;
            }
            return h;
        }
    };
};

// Build a VipKey from the packet's source address.
// Returns false if the packet is malformed or unsuitable (e.g., multicast/unspecified).
bool MakeVipKeyFromSrc(const std::uint8_t *p, std::size_t n, VipKey &out) noexcept;

// Build a VipKey from the packet's destination address.
// Returns false if the packet is malformed or unsuitable (e.g., multicast/unspecified).
bool MakeVipKeyFromDst(const std::uint8_t *p, std::size_t n, VipKey &out) noexcept;
