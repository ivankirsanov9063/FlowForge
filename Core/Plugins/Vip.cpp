#include "Core/Plugins/Vip.hpp"

#include <cstdint>
#include <cstddef>
#include <array>
#include <cstring>  // std::memcpy

namespace {

// ---- helpers ----

    inline bool IsIPv4Multicast(std::uint32_t v4_host) noexcept
    {
        // host-order 0xE0xxxxxx .. 0xEFFFFFFF  (224.0.0.0/4)
        return (v4_host & 0xF0000000u) == 0xE0000000u;
    }

    inline bool IsIPv4Unspecified(std::uint32_t v4_host) noexcept
    {
        return v4_host == 0u; // 0.0.0.0
    }

    inline bool IsIPv6Multicast(const std::array<std::uint8_t,16>& a) noexcept
    {
        return a[0] == 0xFF; // ff00::/8
    }

    inline bool IsIPv6Unspecified(const std::array<std::uint8_t,16>& a) noexcept
    {
        for (auto b : a) if (b != 0) return false;
        return true; // ::/128
    }

    inline std::uint32_t LoadBE32(const std::uint8_t* p) noexcept
    {
        return (static_cast<std::uint32_t>(p[0]) << 24) |
               (static_cast<std::uint32_t>(p[1]) << 16) |
               (static_cast<std::uint32_t>(p[2]) << 8)  |
               (static_cast<std::uint32_t>(p[3])      );
    }

    enum class WhichAddr { Src, Dst };

// Parse raw IP packet (IPv4/IPv6) and extract VipKey by source/destination IP.
    inline bool MakeVipKeyImpl(const std::uint8_t* p, std::size_t n, WhichAddr which, VipKey& out) noexcept
    {
        if (!p || n < 1) return false;

        const std::uint8_t v = p[0] >> 4;
        if (v == 4)
        {
            // IPv4: minimal header 20 bytes
            if (n < 20) return false;
            const std::uint8_t ihl = (p[0] & 0x0Fu) * 4u;
            if (ihl < 20 || ihl > n) return false;

            const std::size_t off = (which == WhichAddr::Src) ? 12u : 16u;
            if (ihl < off + 4u) return false;

            const std::uint32_t addr_be = LoadBE32(p + off);
            // Store in host-order (already converted)
            const std::uint32_t addr_host = addr_be;

            if (IsIPv4Unspecified(addr_host) || IsIPv4Multicast(addr_host))
                return false;

            out = VipKey::FromV4(addr_host);
            return true;
        }
        else if (v == 6)
        {
            // IPv6 fixed 40-byte header
            if (n < 40) return false;

            const std::size_t off = (which == WhichAddr::Src) ? 8u : 24u;
            std::array<std::uint8_t,16> a{};
            std::memcpy(a.data(), p + off, 16u);

            if (IsIPv6Unspecified(a) || IsIPv6Multicast(a))
                return false;

            out = VipKey::FromV6(a);
            return true;
        }

        return false; // unknown version
    }

} // namespace

bool MakeVipKeyFromSrc(const std::uint8_t* p, std::size_t n, VipKey& out) noexcept
{
    return MakeVipKeyImpl(p, n, WhichAddr::Src, out);
}

bool MakeVipKeyFromDst(const std::uint8_t* p, std::size_t n, VipKey& out) noexcept
{
    return MakeVipKeyImpl(p, n, WhichAddr::Dst, out);
}
