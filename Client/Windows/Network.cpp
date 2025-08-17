#include "Network.hpp"

// ============================ HELPERS ============================

std::optional<MIB_IPFORWARD_ROW2> fallback_default_route_excluding(const NET_LUID& exclude) {
    PMIB_IPFORWARD_TABLE2 tbl = nullptr;
    if (GetIpForwardTable2(AF_INET, &tbl) != NO_ERROR) return std::nullopt;
    std::optional<MIB_IPFORWARD_ROW2> best;
    for (ULONG i = 0; i < tbl->NumEntries; ++i) {
        const auto& row = tbl->Table[i];
        if (row.InterfaceLuid.Value == exclude.Value) continue;
        if (row.DestinationPrefix.Prefix.si_family != AF_INET) continue;
        if (row.DestinationPrefix.PrefixLength != 0) continue;
        if (!best || row.Metric < best->Metric) best = row;
    }
    if (tbl) FreeMibTable(tbl);
    return best;
}
std::optional<MIB_IPFORWARD_ROW2> fallback_default_route6_excluding(const NET_LUID& exclude) {
    PMIB_IPFORWARD_TABLE2 tbl = nullptr;
    if (GetIpForwardTable2(AF_INET6, &tbl) != NO_ERROR) return std::nullopt;
    std::optional<MIB_IPFORWARD_ROW2> best;
    for (ULONG i = 0; i < tbl->NumEntries; ++i) {
        const auto& row = tbl->Table[i];
        if (row.InterfaceLuid.Value == exclude.Value) continue;
        if (row.DestinationPrefix.Prefix.si_family != AF_INET6) continue;
        if (row.DestinationPrefix.PrefixLength != 0) continue;
        if (!best || row.Metric < best->Metric) best = row;
    }
    if (tbl) FreeMibTable(tbl);
    return best;
}

// ================================ IPv6 ==================================

bool ipv6_from_string(const char* s, IN6_ADDR& out) { return InetPtonA(AF_INET6, s, &out) == 1; }

bool add_ipv6_address_on_if(const NET_LUID& ifLuid, const char* ip, UINT8 prefixLen) {
    MIB_UNICASTIPADDRESS_ROW row{}; InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid = ifLuid;
    row.Address.si_family = AF_INET6;
    row.Address.Ipv6.sin6_family = AF_INET6;
    row.Address.Ipv6.sin6_scope_id = 0;
    if (!ipv6_from_string(ip, row.Address.Ipv6.sin6_addr)) return false;
    row.PrefixOrigin = IpPrefixOriginManual;
    row.SuffixOrigin = IpSuffixOriginOther;
    row.ValidLifetime = 0xFFFFFFFF;
    row.PreferredLifetime = 0xFFFFFFFF;
    row.DadState = IpDadStatePreferred;
    row.OnLinkPrefixLength = prefixLen;
    DWORD err = CreateUnicastIpAddressEntry(&row);
    if (err == NO_ERROR) return true;
    if (err == ERROR_OBJECT_ALREADY_EXISTS) return SetUnicastIpAddressEntry(&row) == NO_ERROR;
    std::printf("[ERR] CreateUnicastIpAddressEntry(v6 %s/%u) rc=%lu\n", ip, (unsigned)prefixLen, err);
    return false;
}

bool set_if_metric_ipv6(const NET_LUID& ifLuid, ULONG metric) {
    MIB_IPINTERFACE_ROW row{}; InitializeIpInterfaceEntry(&row);
    row.Family = AF_INET6; row.InterfaceLuid = ifLuid;
    if (GetIpInterfaceEntry(&row) != NO_ERROR) return false;
    row.UseAutomaticMetric = FALSE;
    row.Metric = metric;
    DWORD err = SetIpInterfaceEntry(&row);
    if (err == ERROR_INVALID_PARAMETER) { std::printf("[WARN] SetIpInterfaceEntry(v6 metric=%lu) rc=87, ignored\n", metric); return true; }
    if (err != NO_ERROR)              { std::printf("[ERR]  SetIpInterfaceEntry(v6 metric=%lu) rc=%lu\n", metric, err); }
    return err == NO_ERROR;
}
bool set_if_mtu_ipv6(const NET_LUID& ifLuid, ULONG mtu) {
    MIB_IPINTERFACE_ROW row{}; InitializeIpInterfaceEntry(&row);
    row.Family = AF_INET6; row.InterfaceLuid = ifLuid;
    if (GetIpInterfaceEntry(&row) != NO_ERROR) return false;
    row.NlMtu = mtu;
    DWORD err = SetIpInterfaceEntry(&row);
    if (err == ERROR_INVALID_PARAMETER) { std::printf("[WARN] SetIpInterfaceEntry(v6 mtu=%lu) rc=87, ignored\n", mtu); return true; }
    if (err != NO_ERROR)              { std::printf("[ERR]  SetIpInterfaceEntry(v6 mtu=%lu) rc=%lu\n", mtu, err); }
    return err == NO_ERROR;
}

bool add_onlink_host_route6(const NET_LUID& ifLuid, const char* host, ULONG metric) {
    MIB_IPFORWARD_ROW2 r{}; InitializeIpForwardEntry(&r);
    r.InterfaceLuid = ifLuid;
    r.DestinationPrefix.Prefix.si_family = AF_INET6;
    r.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
    if (!ipv6_from_string(host, r.DestinationPrefix.Prefix.Ipv6.sin6_addr)) return false;
    r.DestinationPrefix.PrefixLength = 128;
    r.NextHop.si_family = AF_INET6;
    r.NextHop.Ipv6.sin6_family = AF_INET6;
    std::memset(&r.NextHop.Ipv6.sin6_addr, 0, sizeof(IN6_ADDR)); // on-link
    r.Metric = metric;
    r.Protocol = MIB_IPPROTO_NETMGMT;
    DWORD err = CreateIpForwardEntry2(&r);
    if (!(err == NO_ERROR || err == ERROR_OBJECT_ALREADY_EXISTS))
        std::printf("[ERR] add_onlink_host_route6(%s) rc=%lu\n", host, err);
    return (err == NO_ERROR || err == ERROR_OBJECT_ALREADY_EXISTS);
}

std::optional<MIB_IPFORWARD_ROW2> get_best_route_to6(const char* dest_ip6) {
    SOCKADDR_INET dst{}; dst.si_family = AF_INET6;
    if (!ipv6_from_string(dest_ip6, dst.Ipv6.sin6_addr)) return std::nullopt;
    MIB_IPFORWARD_ROW2 route{};
    if (GetBestRoute2(nullptr, 0, nullptr, &dst, 0, &route, nullptr) != NO_ERROR) return std::nullopt;
    return route;
}

DWORD add_or_update_host_route_via6(const char* host6, const MIB_IPFORWARD_ROW2& via, ULONG metric) {
    if (via.DestinationPrefix.Prefix.si_family != AF_INET6) return ERROR_INVALID_PARAMETER;

    MIB_IPFORWARD_ROW2 desired{}; InitializeIpForwardEntry(&desired);
    desired.InterfaceLuid = via.InterfaceLuid;
    desired.DestinationPrefix.Prefix.si_family = AF_INET6;
    desired.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
    if (!ipv6_from_string(host6, desired.DestinationPrefix.Prefix.Ipv6.sin6_addr))
        return ERROR_INVALID_PARAMETER;
    desired.DestinationPrefix.PrefixLength = 128;

    IN6_ADDR zero{};
    if (via.NextHop.si_family == AF_INET6 &&
        std::memcmp(&via.NextHop.Ipv6.sin6_addr, &zero, sizeof zero) != 0) {
        desired.NextHop = via.NextHop;
    } else {
        desired.NextHop.si_family = AF_INET6;
        desired.NextHop.Ipv6.sin6_family = AF_INET6;
        std::memset(&desired.NextHop.Ipv6.sin6_addr, 0, sizeof(IN6_ADDR)); // on-link
    }
    desired.Metric  = metric;
    desired.Protocol = MIB_IPPROTO_NETMGMT;

    PMIB_IPFORWARD_TABLE2 tbl = nullptr;
    if (GetIpForwardTable2(AF_INET6, &tbl) == NO_ERROR) {
        for (ULONG i = 0; i < tbl->NumEntries; ++i) {
            auto& row = tbl->Table[i];
            if (row.DestinationPrefix.Prefix.si_family == AF_INET6 &&
                row.DestinationPrefix.PrefixLength == 128 &&
                std::memcmp(&row.DestinationPrefix.Prefix.Ipv6.sin6_addr,
                            &desired.DestinationPrefix.Prefix.Ipv6.sin6_addr, sizeof(IN6_ADDR)) == 0) {
                row.InterfaceLuid = desired.InterfaceLuid;
                row.NextHop       = desired.NextHop;
                row.Metric        = desired.Metric;
                row.Protocol      = MIB_IPPROTO_NETMGMT;
                DWORD rc = SetIpForwardEntry2(&row);
                if (rc != NO_ERROR) std::printf("[ERR] SetIpForwardEntry2(v6 /128) rc=%lu\n", rc);
                FreeMibTable(tbl);
                return rc;
            }
        }
        FreeMibTable(tbl);
    }
    DWORD rc = CreateIpForwardEntry2(&desired);
    if (rc != NO_ERROR && rc != ERROR_OBJECT_ALREADY_EXISTS)
        std::printf("[ERR] CreateIpForwardEntry2(v6 /128) rc=%lu\n", rc);
    return rc;
}

bool add_onlink_route_v6(const NET_LUID& ifLuid, const char* prefix, UINT8 prefixLen, ULONG metric) {
    MIB_IPFORWARD_ROW2 r{}; InitializeIpForwardEntry(&r);
    r.InterfaceLuid = ifLuid;

    r.DestinationPrefix.Prefix.si_family = AF_INET6;
    r.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
    if (!ipv6_from_string(prefix, r.DestinationPrefix.Prefix.Ipv6.sin6_addr)) return false;
    r.DestinationPrefix.PrefixLength = prefixLen;

    r.NextHop.si_family = AF_INET6;
    r.NextHop.Ipv6.sin6_family = AF_INET6;
    std::memset(&r.NextHop.Ipv6.sin6_addr, 0, sizeof(IN6_ADDR)); // on-link

    r.Metric   = metric;
    r.Protocol = MIB_IPPROTO_NETMGMT;

    DWORD err = CreateIpForwardEntry2(&r);
    if (!(err == NO_ERROR || err == ERROR_OBJECT_ALREADY_EXISTS))
        std::printf("[ERR] add_onlink_route_v6(%s/%u) rc=%lu\n", prefix, (unsigned)prefixLen, err);
    return (err == NO_ERROR || err == ERROR_OBJECT_ALREADY_EXISTS);
}

// ================================ IPv4 ==================================

bool ipv4_from_string(const char* s, IN_ADDR& out) { return InetPtonA(AF_INET, s, &out) == 1; }

bool add_ipv4_address_on_if(const NET_LUID& ifLuid, const char* ip, UINT8 prefixLen) {
    MIB_UNICASTIPADDRESS_ROW row{}; InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid = ifLuid;
    row.Address.si_family = AF_INET;
    if (!ipv4_from_string(ip, row.Address.Ipv4.sin_addr)) return false;
    row.PrefixOrigin = IpPrefixOriginManual;
    row.SuffixOrigin = IpSuffixOriginOther;
    row.ValidLifetime = 0xFFFFFFFF;
    row.PreferredLifetime = 0xFFFFFFFF;
    row.DadState = IpDadStatePreferred;
    row.OnLinkPrefixLength = prefixLen;

    DWORD err = CreateUnicastIpAddressEntry(&row);
    if (err == NO_ERROR) return true;
    if (err == ERROR_OBJECT_ALREADY_EXISTS) return SetUnicastIpAddressEntry(&row) == NO_ERROR;
    std::printf("[ERR] CreateUnicastIpAddressEntry(v4 %s/%u) rc=%lu\n", ip, (unsigned)prefixLen, err);
    return false;
}

bool add_onlink_host_route(const NET_LUID& ifLuid, const char* host, ULONG metric) {
    MIB_IPFORWARD_ROW2 r{}; InitializeIpForwardEntry(&r);
    r.InterfaceLuid = ifLuid;
    r.DestinationPrefix.Prefix.si_family = AF_INET;
    if (!ipv4_from_string(host, r.DestinationPrefix.Prefix.Ipv4.sin_addr)) return false;
    r.DestinationPrefix.PrefixLength = 32;
    r.NextHop.si_family = AF_INET;            // on-link
    r.NextHop.Ipv4.sin_addr.S_un.S_addr = 0;  // 0.0.0.0
    r.Metric = metric;
    r.Protocol = MIB_IPPROTO_NETMGMT;
    DWORD err = CreateIpForwardEntry2(&r);
    if (!(err == NO_ERROR || err == ERROR_OBJECT_ALREADY_EXISTS))
        std::printf("[ERR] add_onlink_host_route(%s) rc=%lu\n", host, err);
    return (err == NO_ERROR || err == ERROR_OBJECT_ALREADY_EXISTS);
}

std::optional<MIB_IPFORWARD_ROW2> get_best_route_to(const char* dest_ip) {
    SOCKADDR_INET dst{}; dst.si_family = AF_INET;
    if (!ipv4_from_string(dest_ip, dst.Ipv4.sin_addr)) return std::nullopt;
    MIB_IPFORWARD_ROW2 route{};
    if (GetBestRoute2(nullptr, 0, nullptr, &dst, 0, &route, nullptr) != NO_ERROR) return std::nullopt;
    return route;
}

DWORD add_or_update_host_route_via(const char* host, const MIB_IPFORWARD_ROW2& via, ULONG metric) {
    if (via.DestinationPrefix.Prefix.si_family != AF_INET) return ERROR_INVALID_PARAMETER;

    MIB_IPFORWARD_ROW2 desired{}; InitializeIpForwardEntry(&desired);
    desired.InterfaceLuid = via.InterfaceLuid;
    desired.DestinationPrefix.Prefix.si_family = AF_INET;
    if (!ipv4_from_string(host, desired.DestinationPrefix.Prefix.Ipv4.sin_addr))
        return ERROR_INVALID_PARAMETER;
    desired.DestinationPrefix.PrefixLength = 32;

    if (via.NextHop.si_family == AF_INET && via.NextHop.Ipv4.sin_addr.S_un.S_addr != 0) {
        desired.NextHop = via.NextHop; // через конкретный шлюз
    } else {
        desired.NextHop.si_family = AF_INET;
        desired.NextHop.Ipv4.sin_addr.S_un.S_addr = 0; // on-link
    }
    desired.Metric = metric;
    desired.Protocol = MIB_IPPROTO_NETMGMT;

    PMIB_IPFORWARD_TABLE2 tbl = nullptr;
    if (GetIpForwardTable2(AF_INET, &tbl) == NO_ERROR) {
        for (ULONG i = 0; i < tbl->NumEntries; ++i) {
            auto &row = tbl->Table[i];
            if (row.DestinationPrefix.Prefix.si_family == AF_INET &&
                row.DestinationPrefix.PrefixLength == 32 &&
                row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr ==
                    desired.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr) {
                row.InterfaceLuid = desired.InterfaceLuid;
                row.NextHop       = desired.NextHop;
                row.Metric        = desired.Metric;
                row.Protocol      = MIB_IPPROTO_NETMGMT;
                DWORD rc = SetIpForwardEntry2(&row);
                if (rc != NO_ERROR) std::printf("[ERR] SetIpForwardEntry2(v4 /32) rc=%lu\n", rc);
                FreeMibTable(tbl);
                return rc;
            }
        }
        FreeMibTable(tbl);
    }
    DWORD rc = CreateIpForwardEntry2(&desired);
    if (rc == NO_ERROR || rc == ERROR_OBJECT_ALREADY_EXISTS) return rc;

    // Legacy fallback (Win7)
    std::printf("[WARN] CreateIpForwardEntry2(v4 /32) rc=%lu, trying legacy API...\n", rc);
    MIB_IPFORWARDROW r{};
    r.dwForwardDest    = desired.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr;
    r.dwForwardMask    = 0xFFFFFFFF;
    r.dwForwardPolicy  = 0;
    r.dwForwardNextHop = desired.NextHop.Ipv4.sin_addr.S_un.S_addr; // 0 = on-link
    r.dwForwardIfIndex = via.InterfaceIndex;                        // IfIndex из via
    r.dwForwardType    = (r.dwForwardNextHop == 0) ? 3 /*DIRECT*/ : 4 /*INDIRECT*/;
    r.dwForwardProto   = MIB_IPPROTO_NETMGMT;
    r.dwForwardMetric1 = metric;
    DWORD rc2 = CreateIpForwardEntry(&r);
    if (rc2 != NO_ERROR && rc2 != ERROR_OBJECT_ALREADY_EXISTS)
        std::printf("[ERR] CreateIpForwardEntry(legacy v4 /32) rc=%lu\n", rc2);
    else
        std::printf("[OK ] legacy v4 /32 pinned via IfIndex=%u\n", r.dwForwardIfIndex);
    return rc2;
}

bool set_if_metric_ipv4(const NET_LUID& ifLuid, ULONG metric) {
    MIB_IPINTERFACE_ROW row{}; InitializeIpInterfaceEntry(&row);
    row.Family = AF_INET; row.InterfaceLuid = ifLuid;
    if (GetIpInterfaceEntry(&row) != NO_ERROR) return false;
    row.UseAutomaticMetric = FALSE;
    row.Metric = metric;
    DWORD err = SetIpInterfaceEntry(&row);
    if (err == ERROR_INVALID_PARAMETER) { std::printf("[WARN] SetIpInterfaceEntry(v4 metric=%lu) rc=87, ignored\n", metric); return true; }
    if (err != NO_ERROR)              { std::printf("[ERR]  SetIpInterfaceEntry(v4 metric=%lu) rc=%lu\n", metric, err); }
    return err == NO_ERROR;
}

bool set_if_mtu_ipv4(const NET_LUID& ifLuid, ULONG mtu) {
    MIB_IPINTERFACE_ROW row{}; InitializeIpInterfaceEntry(&row);
    row.Family = AF_INET; row.InterfaceLuid = ifLuid;
    if (GetIpInterfaceEntry(&row) != NO_ERROR) return false;
    row.NlMtu = mtu;
    DWORD err = SetIpInterfaceEntry(&row);
    if (err == ERROR_INVALID_PARAMETER) { std::printf("[WARN] SetIpInterfaceEntry(v4 mtu=%lu) rc=87, ignored\n", mtu); return true; }
    if (err != NO_ERROR)              { std::printf("[ERR]  SetIpInterfaceEntry(v4 mtu=%lu) rc=%lu\n", mtu, err); }
    return err == NO_ERROR;
}

bool add_onlink_route_v4(const NET_LUID& ifLuid, const char* prefix, UINT8 prefixLen, ULONG metric) {
    MIB_IPFORWARD_ROW2 r{}; InitializeIpForwardEntry(&r);
    r.InterfaceLuid = ifLuid;
    r.DestinationPrefix.Prefix.si_family = AF_INET;
    if (!ipv4_from_string(prefix, r.DestinationPrefix.Prefix.Ipv4.sin_addr)) return false;
    r.DestinationPrefix.PrefixLength = prefixLen;
    r.NextHop.si_family = AF_INET;            // on-link
    r.NextHop.Ipv4.sin_addr.S_un.S_addr = 0;  // 0.0.0.0
    r.Metric = metric;
    r.Protocol = MIB_IPPROTO_NETMGMT;
    DWORD err = CreateIpForwardEntry2(&r);
    if (!(err == NO_ERROR || err == ERROR_OBJECT_ALREADY_EXISTS))
        std::printf("[ERR] add_onlink_route_v4(%s/%u) rc=%lu\n", prefix, (unsigned)prefixLen, err);
    return (err == NO_ERROR || err == ERROR_OBJECT_ALREADY_EXISTS);
}
// ============================== PHASES ===============================

static const char* LOCAL4 = "10.8.0.2";
static const char* PEER4  = "10.8.0.1";
static const char* LOCAL6 = "fd00:dead:beef::2";
static const char* PEER6  = "fd00:dead:beef::1";

int ConfigureNetwork_Base(WINTUN_ADAPTER_HANDLE adapter)
{
    NET_LUID luid{}; Wintun.GetLuid(adapter, &luid);

    // MTU
    set_if_mtu_ipv4(luid, 1400);
    set_if_mtu_ipv6(luid, 1400);

    // IPv4: присваиваем адрес как /30 (point-to-point), а не /32
    if (!add_ipv4_address_on_if(luid, LOCAL4, 30)) {
        std::printf("[FATAL] failed to assign IPv4 %s/30 on Wintun\n", LOCAL4);
        return 1;
    }

    // IPv6: присваиваем адрес как /64 (или /127 для p2p), а не /128
    add_ipv6_address_on_if(luid, LOCAL6, 64);

    // Метрики интерфейса (самые низкие для приоритета)
    set_if_metric_ipv4(luid, 1);
    set_if_metric_ipv6(luid, 1);

    std::printf("[OK ] Base configured (IPs as subnets, MTU, metrics)\n");
    return 0;
}

bool ConfigureNetwork_PinServer(WINTUN_ADAPTER_HANDLE adapter, const std::string& server_ip)
{
    NET_LUID luid{}; Wintun.GetLuid(adapter, &luid);
    bool isV6 = (server_ip.find(':') != std::string::npos);

    if (!isV6) {
        auto best = get_best_route_to(server_ip.c_str());
        if (!best) best = fallback_default_route_excluding(luid);
        if (!best) { std::printf("[WARN] no v4 route to server before switch\n"); return false; }
        DWORD rc = add_or_update_host_route_via(server_ip.c_str(), *best, 1);
        if (rc == NO_ERROR || rc == ERROR_OBJECT_ALREADY_EXISTS) {
            std::printf("[OK ] pinned v4 /32 to %s via IfLuid=%llu\n",
                        server_ip.c_str(), (unsigned long long)best->InterfaceLuid.Value);
            return true;
        }
        std::printf("[ERR] pin v4 /32 to %s rc=%lu\n", server_ip.c_str(), rc);
        return false;
    } else {
        auto best6 = get_best_route_to6(server_ip.c_str());
        if (!best6) best6 = fallback_default_route6_excluding(luid);
        if (!best6) { std::printf("[WARN] no v6 route to server before switch\n"); return false; }
        DWORD rc = add_or_update_host_route_via6(server_ip.c_str(), *best6, 1);
        if (rc == NO_ERROR || rc == ERROR_OBJECT_ALREADY_EXISTS) {
            std::printf("[OK ] pinned v6 /128 to %s via IfLuid=%llu\n",
                        server_ip.c_str(), (unsigned long long)best6->InterfaceLuid.Value);
            return true;
        }
        std::printf("[ERR] pin v6 /128 to %s rc=%lu\n", server_ip.c_str(), rc);
        return false;
    }
}

bool ConfigureNetwork_ActivateDefaults(WINTUN_ADAPTER_HANDLE adapter)
{
    NET_LUID luid{}; Wintun.GetLuid(adapter, &luid);

    // IPv4: split-default через VPN peer
    bool ok41 = add_route_via_gateway_v4(luid, "0.0.0.0",   1, PEER4, 1);
    bool ok42 = add_route_via_gateway_v4(luid, "128.0.0.0", 1, PEER4, 1);

    // IPv6: split-default через VPN peer
    bool ok61 = add_route_via_gateway_v6(luid, "::",     1, PEER6, 1);
    bool ok62 = add_route_via_gateway_v6(luid, "8000::", 1, PEER6, 1);

    if (!(ok41 && ok42)) std::printf("[ERR] v4 split-default failed (0/1=%d 128/1=%d)\n", ok41?1:0, ok42?1:0);
    if (!(ok61 && ok62)) std::printf("[ERR] v6 split-default failed (::/1=%d 8000::/1=%d)\n", ok61?1:0, ok62?1:0);

    bool any = (ok41 && ok42) || (ok61 && ok62);
    if (any) std::printf("[OK ] defaults activated via VPN gateway (v4:%d v6:%d)\n", (ok41&&ok42)?1:0, (ok61&&ok62)?1:0);
    return any;
}

// Новые функции для маршрутизации через VPN gateway
bool add_route_via_gateway_v4(const NET_LUID& ifLuid, const char* prefix, UINT8 prefixLen, const char* gateway_ip, ULONG metric) {
    MIB_IPFORWARD_ROW2 r{}; InitializeIpForwardEntry(&r);
    r.InterfaceLuid = ifLuid;

    // Destination
    r.DestinationPrefix.Prefix.si_family = AF_INET;
    if (!ipv4_from_string(prefix, r.DestinationPrefix.Prefix.Ipv4.sin_addr)) return false;
    r.DestinationPrefix.PrefixLength = prefixLen;

    // Gateway (next-hop)
    r.NextHop.si_family = AF_INET;
    if (!ipv4_from_string(gateway_ip, r.NextHop.Ipv4.sin_addr)) return false;

    r.Metric = metric;
    r.Protocol = MIB_IPPROTO_NETMGMT;

    DWORD err = CreateIpForwardEntry2(&r);
    if (!(err == NO_ERROR || err == ERROR_OBJECT_ALREADY_EXISTS))
        std::printf("[ERR] add_route_via_gateway_v4(%s/%u via %s) rc=%lu\n", prefix, (unsigned)prefixLen, gateway_ip, err);
    return (err == NO_ERROR || err == ERROR_OBJECT_ALREADY_EXISTS);
}

bool add_route_via_gateway_v6(const NET_LUID& ifLuid, const char* prefix, UINT8 prefixLen, const char* gateway_ip6, ULONG metric) {
    MIB_IPFORWARD_ROW2 r{}; InitializeIpForwardEntry(&r);
    r.InterfaceLuid = ifLuid;

    // Destination
    r.DestinationPrefix.Prefix.si_family = AF_INET6;
    r.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
    if (!ipv6_from_string(prefix, r.DestinationPrefix.Prefix.Ipv6.sin6_addr)) return false;
    r.DestinationPrefix.PrefixLength = prefixLen;

    // Gateway (next-hop)
    r.NextHop.si_family = AF_INET6;
    r.NextHop.Ipv6.sin6_family = AF_INET6;
    if (!ipv6_from_string(gateway_ip6, r.NextHop.Ipv6.sin6_addr)) return false;

    r.Metric = metric;
    r.Protocol = MIB_IPPROTO_NETMGMT;

    DWORD err = CreateIpForwardEntry2(&r);
    if (!(err == NO_ERROR || err == ERROR_OBJECT_ALREADY_EXISTS))
        std::printf("[ERR] add_route_via_gateway_v6(%s/%u via %s) rc=%lu\n", prefix, (unsigned)prefixLen, gateway_ip6, err);
    return (err == NO_ERROR || err == ERROR_OBJECT_ALREADY_EXISTS);
}
