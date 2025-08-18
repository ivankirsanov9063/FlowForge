#include "Network.hpp"

// ============================ HELPERS ============================

namespace Network
{

namespace
{
    inline bool is_v6_string(const std::string &s)
    {
        return s.find(':') != std::string::npos;
    }

    bool ipv4_from_string_(const char *s, IN_ADDR &out)
    {
        return InetPtonA(AF_INET, s, &out) == 1;
    }

    bool ipv6_from_string_(const char *s, IN6_ADDR &out)
    {
        return InetPtonA(AF_INET6, s, &out) == 1;
    }

    ADDRESS_FAMILY fam(IpVersion ver)
    {
        return (ver == IpVersion::V6) ? AF_INET6 : AF_INET;
    }

    const char *family_tag(IpVersion ver)
    {
        return (ver == IpVersion::V6) ? "v6" : "v4";
    }

    // Локальные адреса/peer — как и раньше
    static const char *LOCAL4 = "10.8.0.2";
    static const char *PEER4  = "10.8.0.1";
    static const char *LOCAL6 = "fd00:dead:beef::2";
    static const char *PEER6  = "fd00:dead:beef::1";
}

// ---------------- low-level generic ----------------

void set_if_metric(const NET_LUID &ifLuid,
                   ULONG metric,
                   IpVersion ver)
{
    MIB_IPINTERFACE_ROW row{};
    InitializeIpInterfaceEntry(&row);
    row.Family = fam(ver);
    row.InterfaceLuid = ifLuid;
    if (GetIpInterfaceEntry(&row) != NO_ERROR)
    {
        throw std::runtime_error("GetIpInterfaceEntry failed for metric");
    }

    row.UseAutomaticMetric = FALSE;
    row.Metric = metric;

    DWORD err = SetIpInterfaceEntry(&row);
    if (err == ERROR_INVALID_PARAMETER)
    {
        std::printf("[WARN] SetIpInterfaceEntry(%s metric=%lu) rc=87, ignored\n",
                    family_tag(ver), metric);
        return;
    }
    if (err != NO_ERROR)
    {
        throw std::runtime_error("SetIpInterfaceEntry(metric) failed");
    }
}

void set_if_mtu(const NET_LUID &ifLuid,
                ULONG mtu,
                IpVersion ver)
{
    MIB_IPINTERFACE_ROW row{};
    InitializeIpInterfaceEntry(&row);
    row.Family = fam(ver);
    row.InterfaceLuid = ifLuid;
    if (GetIpInterfaceEntry(&row) != NO_ERROR)
    {
        throw std::runtime_error("GetIpInterfaceEntry failed for mtu");
    }

    row.NlMtu = mtu;

    DWORD err = SetIpInterfaceEntry(&row);
    if (err == ERROR_INVALID_PARAMETER)
    {
        std::printf("[WARN] SetIpInterfaceEntry(%s mtu=%lu) rc=87, ignored\n",
                    family_tag(ver), mtu);
        return;
    }
    if (err != NO_ERROR)
    {
        throw std::runtime_error("SetIpInterfaceEntry(mtu) failed");
    }
}

void add_ip_address_on_if(const NET_LUID &ifLuid,
                          const char *ip,
                          UINT8 prefixLen,
                          IpVersion ver)
{
    MIB_UNICASTIPADDRESS_ROW row{};
    InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid = ifLuid;
    row.Address.si_family = fam(ver);

    if (ver == IpVersion::V6)
    {
        row.Address.Ipv6.sin6_family = AF_INET6;
        row.Address.Ipv6.sin6_scope_id = 0;
        if (!ipv6_from_string_(ip, row.Address.Ipv6.sin6_addr))
        {
            throw std::invalid_argument("add_ip_address_on_if: invalid IPv6");
        }
    }
    else
    {
        if (!ipv4_from_string_(ip, row.Address.Ipv4.sin_addr))
        {
            throw std::invalid_argument("add_ip_address_on_if: invalid IPv4");
        }
    }

    row.PrefixOrigin = IpPrefixOriginManual;
    row.SuffixOrigin = IpSuffixOriginOther;
    row.ValidLifetime = 0xFFFFFFFF;
    row.PreferredLifetime = 0xFFFFFFFF;
    row.DadState = IpDadStatePreferred;
    row.OnLinkPrefixLength = prefixLen;

    DWORD err = CreateUnicastIpAddressEntry(&row);
    if (err == NO_ERROR) return;
    if (err == ERROR_OBJECT_ALREADY_EXISTS)
    {
        if (SetUnicastIpAddressEntry(&row) == NO_ERROR) return;
    }
    std::printf("[ERR] Create/SetUnicastIpAddressEntry(%s %s/%u) rc=%lu\n",
                family_tag(ver), ip, static_cast<unsigned>(prefixLen), err);
    throw std::runtime_error("add_ip_address_on_if failed");
}

void add_onlink_host_route(const NET_LUID &ifLuid,
                           const char *ip,
                           ULONG metric,
                           IpVersion ver)
{
    MIB_IPFORWARD_ROW2 r{};
    InitializeIpForwardEntry(&r);
    r.InterfaceLuid = ifLuid;

    r.DestinationPrefix.Prefix.si_family = fam(ver);
    if (ver == IpVersion::V6)
    {
        r.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
        if (!ipv6_from_string_(ip, r.DestinationPrefix.Prefix.Ipv6.sin6_addr))
        {
            throw std::invalid_argument("add_onlink_host_route: invalid IPv6");
        }
        r.DestinationPrefix.PrefixLength = 128;
        r.NextHop.si_family = AF_INET6;
        r.NextHop.Ipv6.sin6_family = AF_INET6;
        std::memset(&r.NextHop.Ipv6.sin6_addr, 0, sizeof(IN6_ADDR)); // on-link
    }
    else
    {
        if (!ipv4_from_string_(ip, r.DestinationPrefix.Prefix.Ipv4.sin_addr))
        {
            throw std::invalid_argument("add_onlink_host_route: invalid IPv4");
        }
        r.DestinationPrefix.PrefixLength = 32;
        r.NextHop.si_family = AF_INET;           // on-link
        r.NextHop.Ipv4.sin_addr.S_un.S_addr = 0; // 0.0.0.0
    }

    r.Metric   = metric;
    r.Protocol = MIB_IPPROTO_NETMGMT;

    DWORD err = CreateIpForwardEntry2(&r);
    if (!(err == NO_ERROR || err == ERROR_OBJECT_ALREADY_EXISTS))
    {
        std::printf("[ERR] add_onlink_host_route(%s %s) rc=%lu\n", family_tag(ver), ip, err);
        throw std::runtime_error("add_onlink_host_route failed");
    }
}

void add_onlink_route(const NET_LUID &ifLuid,
                      const char *prefix,
                      UINT8 prefixLen,
                      ULONG metric,
                      IpVersion ver)
{
    MIB_IPFORWARD_ROW2 r{};
    InitializeIpForwardEntry(&r);
    r.InterfaceLuid = ifLuid;

    r.DestinationPrefix.Prefix.si_family = fam(ver);
    if (ver == IpVersion::V6)
    {
        r.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
        if (!ipv6_from_string_(prefix, r.DestinationPrefix.Prefix.Ipv6.sin6_addr))
        {
            throw std::invalid_argument("add_onlink_route: invalid IPv6 prefix");
        }
    }
    else
    {
        if (!ipv4_from_string_(prefix, r.DestinationPrefix.Prefix.Ipv4.sin_addr))
        {
            throw std::invalid_argument("add_onlink_route: invalid IPv4 prefix");
        }
    }
    r.DestinationPrefix.PrefixLength = prefixLen;

    r.NextHop.si_family = fam(ver); // on-link
    if (ver == IpVersion::V6)
    {
        r.NextHop.Ipv6.sin6_family = AF_INET6;
        std::memset(&r.NextHop.Ipv6.sin6_addr, 0, sizeof(IN6_ADDR));
    }
    else
    {
        r.NextHop.Ipv4.sin_addr.S_un.S_addr = 0;
    }

    r.Metric   = metric;
    r.Protocol = MIB_IPPROTO_NETMGMT;

    DWORD err = CreateIpForwardEntry2(&r);
    if (!(err == NO_ERROR || err == ERROR_OBJECT_ALREADY_EXISTS))
    {
        std::printf("[ERR] add_onlink_route(%s %s/%u) rc=%lu\n",
                    family_tag(ver), prefix, static_cast<unsigned>(prefixLen), err);
        throw std::runtime_error("add_onlink_route failed");
    }
}

std::optional<MIB_IPFORWARD_ROW2> get_best_route_to_generic(const char *dest_ip,
                                                            IpVersion ver)
{
    SOCKADDR_INET dst{};
    dst.si_family = fam(ver);
    if (ver == IpVersion::V6)
    {
        if (!ipv6_from_string_(dest_ip, dst.Ipv6.sin6_addr))
        {
            throw std::invalid_argument("get_best_route_to_generic: invalid IPv6");
        }
    }
    else
    {
        if (!ipv4_from_string_(dest_ip, dst.Ipv4.sin_addr))
        {
            throw std::invalid_argument("get_best_route_to_generic: invalid IPv4");
        }
    }

    MIB_IPFORWARD_ROW2 route{};
    DWORD rc = GetBestRoute2(nullptr, 0, nullptr, &dst, 0, &route, nullptr);
    if (rc == NO_ERROR)
    {
        return route;
    }
    // нет маршрута — это не ошибка, просто отсутствует
    return std::nullopt;
}

std::optional<MIB_IPFORWARD_ROW2> fallback_default_route_excluding(const NET_LUID &exclude,
                                                                   IpVersion ver)
{
    PMIB_IPFORWARD_TABLE2 tbl = nullptr;
    DWORD rc = GetIpForwardTable2(fam(ver), &tbl);
    if (rc != NO_ERROR)
    {
        throw std::runtime_error("GetIpForwardTable2 failed");
    }

    std::optional<MIB_IPFORWARD_ROW2> best;
    for (ULONG i = 0; i < tbl->NumEntries; ++i)
    {
        const auto &row = tbl->Table[i];
        if (row.InterfaceLuid.Value == exclude.Value)                         continue;
        if (row.DestinationPrefix.Prefix.si_family != fam(ver))               continue;
        if (row.DestinationPrefix.PrefixLength != 0)                          continue;
        if (!best || row.Metric < best->Metric) best = row;
    }
    if (tbl) FreeMibTable(tbl);
    return best;
}

void add_or_update_host_route_via(const char *host,
                                  const MIB_IPFORWARD_ROW2 &via,
                                  ULONG metric,
                                  IpVersion ver)
{
    if (via.DestinationPrefix.Prefix.si_family != fam(ver))
    {
        throw std::invalid_argument("add_or_update_host_route_via: family mismatch");
    }

    MIB_IPFORWARD_ROW2 desired{};
    InitializeIpForwardEntry(&desired);
    desired.InterfaceLuid = via.InterfaceLuid;

    desired.DestinationPrefix.Prefix.si_family = fam(ver);
    if (ver == IpVersion::V6)
    {
        desired.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
        if (!ipv6_from_string_(host, desired.DestinationPrefix.Prefix.Ipv6.sin6_addr))
        {
            throw std::invalid_argument("add_or_update_host_route_via: invalid IPv6");
        }
        desired.DestinationPrefix.PrefixLength = 128;
    }
    else
    {
        if (!ipv4_from_string_(host, desired.DestinationPrefix.Prefix.Ipv4.sin_addr))
        {
            throw std::invalid_argument("add_or_update_host_route_via: invalid IPv4");
        }
        desired.DestinationPrefix.PrefixLength = 32;
    }

    // next-hop: если в via задан gateway — используем его, иначе on-link
    if (via.NextHop.si_family == fam(ver))
    {
        desired.NextHop = via.NextHop;
    }
    else
    {
        desired.NextHop.si_family = fam(ver);
        if (ver == IpVersion::V6)
        {
            desired.NextHop.Ipv6.sin6_family = AF_INET6;
            std::memset(&desired.NextHop.Ipv6.sin6_addr, 0, sizeof(IN6_ADDR)); // on-link
        }
        else
        {
            desired.NextHop.Ipv4.sin_addr.S_un.S_addr = 0; // 0.0.0.0 on-link
        }
    }

    desired.Metric   = metric;
    desired.Protocol = MIB_IPPROTO_NETMGMT;

    // Пытаемся обновить существующую запись /32 или /128
    PMIB_IPFORWARD_TABLE2 tbl = nullptr;
    if (GetIpForwardTable2(fam(ver), &tbl) == NO_ERROR)
    {
        for (ULONG i = 0; i < tbl->NumEntries; ++i)
        {
            auto &row = tbl->Table[i];
            if (row.DestinationPrefix.Prefix.si_family != fam(ver)) continue;
            if (row.DestinationPrefix.PrefixLength != (ver == IpVersion::V6 ? 128 : 32)) continue;

            bool same = false;
            if (ver == IpVersion::V6)
            {
                same = (std::memcmp(&row.DestinationPrefix.Prefix.Ipv6.sin6_addr,
                                    &desired.DestinationPrefix.Prefix.Ipv6.sin6_addr,
                                    sizeof(IN6_ADDR)) == 0);
            }
            else
            {
                same = (row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr ==
                        desired.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr);
            }

            if (same)
            {
                row.InterfaceLuid = desired.InterfaceLuid;
                row.NextHop       = desired.NextHop;
                row.Metric        = desired.Metric;
                row.Protocol      = MIB_IPPROTO_NETMGMT;
                DWORD rc = SetIpForwardEntry2(&row);
                FreeMibTable(tbl);
                if (rc != NO_ERROR)
                {
                    throw std::runtime_error("SetIpForwardEntry2(/host) failed");
                }
                return;
            }
        }
        FreeMibTable(tbl);
    }

    // Иначе создаём
    DWORD rc = CreateIpForwardEntry2(&desired);
    if (rc == NO_ERROR || rc == ERROR_OBJECT_ALREADY_EXISTS)
    {
        return;
    }

    // Fallback для Win7 (только IPv4)
    if (ver == IpVersion::V6)
    {
        std::printf("[ERR] CreateIpForwardEntry2(v6 /128) rc=%lu\n", rc);
        throw std::runtime_error("CreateIpForwardEntry2(v6 /128) failed");
    }

    std::printf("[WARN] CreateIpForwardEntry2(v4 /32) rc=%lu, trying legacy API...\n", rc);

    MIB_IPFORWARDROW r{};
    r.dwForwardDest   = desired.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr;
    r.dwForwardMask   = 0xFFFFFFFF;
    r.dwForwardPolicy = 0;
    r.dwForwardNextHop = desired.NextHop.Ipv4.sin_addr.S_un.S_addr; // 0 = on-link
    r.dwForwardIfIndex = via.InterfaceIndex;                        // IfIndex из via
    r.dwForwardType    = (r.dwForwardNextHop == 0) ? 3 /*DIRECT*/ : 4 /*INDIRECT*/;
    r.dwForwardProto   = MIB_IPPROTO_NETMGMT;
    r.dwForwardMetric1 = metric;

    DWORD rc2 = CreateIpForwardEntry(&r);
    if (!(rc2 == NO_ERROR || rc2 == ERROR_OBJECT_ALREADY_EXISTS))
    {
        std::printf("[ERR] CreateIpForwardEntry(legacy v4 /32) rc=%lu\n", rc2);
        throw std::runtime_error("CreateIpForwardEntry(legacy v4 /32) failed");
    }
}

void add_route_via_gateway(const NET_LUID &ifLuid,
                           const char *prefix,
                           UINT8 prefixLen,
                           const char *gateway,
                           ULONG metric,
                           IpVersion ver)
{
    MIB_IPFORWARD_ROW2 r{};
    InitializeIpForwardEntry(&r);
    r.InterfaceLuid = ifLuid;

    r.DestinationPrefix.Prefix.si_family = fam(ver);
    if (ver == IpVersion::V6)
    {
        r.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
        if (!ipv6_from_string_(prefix, r.DestinationPrefix.Prefix.Ipv6.sin6_addr))
        {
            throw std::invalid_argument("add_route_via_gateway: invalid IPv6 prefix");
        }
    }
    else
    {
        if (!ipv4_from_string_(prefix, r.DestinationPrefix.Prefix.Ipv4.sin_addr))
        {
            throw std::invalid_argument("add_route_via_gateway: invalid IPv4 prefix");
        }
    }
    r.DestinationPrefix.PrefixLength = prefixLen;

    r.NextHop.si_family = fam(ver);
    if (ver == IpVersion::V6)
    {
        r.NextHop.Ipv6.sin6_family = AF_INET6;
        if (!ipv6_from_string_(gateway, r.NextHop.Ipv6.sin6_addr))
        {
            throw std::invalid_argument("add_route_via_gateway: invalid IPv6 gateway");
        }
    }
    else
    {
        if (!ipv4_from_string_(gateway, r.NextHop.Ipv4.sin_addr))
        {
            throw std::invalid_argument("add_route_via_gateway: invalid IPv4 gateway");
        }
    }

    r.Metric   = metric;
    r.Protocol = MIB_IPPROTO_NETMGMT;

    DWORD err = CreateIpForwardEntry2(&r);
    if (!(err == NO_ERROR || err == ERROR_OBJECT_ALREADY_EXISTS))
    {
        std::printf("[ERR] add_route_via_gateway(%s %s/%u via %s) rc=%lu\n",
                    family_tag(ver), prefix, static_cast<unsigned>(prefixLen), gateway, err);
        throw std::runtime_error("add_route_via_gateway failed");
    }
}

// ============================== ONE-FAMILY FACADE ===============================

void ConfigureNetwork(WINTUN_ADAPTER_HANDLE adapter,
                      const std::string &server_ip,
                      IpVersion ver)
{
    if (!adapter)
    {
        throw std::invalid_argument("ConfigureNetwork: null adapter");
    }

    NET_LUID luid{};
    Wintun.GetLuid(adapter, &luid);

    // MTU + адрес + метрика
    set_if_mtu(luid, 1400, ver);
    if (ver == IpVersion::V6)
    {
        // IPv6: присваиваем адрес как /64 (или /127 для p2p), а не /128
        add_ip_address_on_if(luid, LOCAL6, 64, IpVersion::V6);
        set_if_metric(luid, 1, IpVersion::V6);
    }
    else
    {
        // IPv4: присваиваем адрес как /30 (point-to-point), а не /32
        add_ip_address_on_if(luid, LOCAL4, 30, IpVersion::V4);
        set_if_metric(luid, 1, IpVersion::V4);
    }

    // Пин до сервера (только если семейство совпадает с server_ip)
    const bool server_is_v6 = is_v6_string(server_ip);
    const bool need_pin = ((ver == IpVersion::V6) == server_is_v6);
    bool pinned = false;

    if (need_pin)
    {
        auto best = get_best_route_to_generic(server_ip.c_str(), ver);
        if (!best)
        {
            best = fallback_default_route_excluding(luid, ver);
        }

        if (best)
        {
            add_or_update_host_route_via(server_ip.c_str(), *best, 1, ver);
            std::printf("[OK ] pinned %s host route to %s via IfLuid=%llu\n",
                        family_tag(ver),
                        server_ip.c_str(),
                        static_cast<unsigned long long>(best->InterfaceLuid.Value));
            pinned = true;
        }
        else
        {
            std::printf("[WARN] no %s route to server before switch\n", family_tag(ver));
        }
    }

    // Активируем split-default через VPN peer — только если pinned успешно
    if (pinned)
    {
        if (ver == IpVersion::V6)
        {
            add_route_via_gateway(luid, "::",      1, PEER6, 1, IpVersion::V6);
            add_route_via_gateway(luid, "8000::",  1, PEER6, 1, IpVersion::V6);
        }
        else
        {
            add_route_via_gateway(luid, "0.0.0.0",   1, PEER4, 1, IpVersion::V4);
            add_route_via_gateway(luid, "128.0.0.0", 1, PEER4, 1, IpVersion::V4);
        }
        std::printf("[OK ] defaults activated via VPN gateway (%s)\n", family_tag(ver));
    }
}

} // namespace Network
