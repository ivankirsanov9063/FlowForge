#include "Network.hpp"

std::optional<MIB_IPFORWARD_ROW2> fallback_default_route_excluding(const NET_LUID& exclude) {
    PMIB_IPFORWARD_TABLE2 tbl = nullptr;
    if (GetIpForwardTable2(AF_INET, &tbl) != NO_ERROR) return std::nullopt;
    std::optional<MIB_IPFORWARD_ROW2> best;
    for (ULONG i = 0; i < tbl->NumEntries; ++i) {
        const auto& row = tbl->Table[i];
        if (row.InterfaceLuid.Value == exclude.Value) continue;      // не Wintun
        if (row.DestinationPrefix.PrefixLength != 0) continue;       // только дефолт 0/0
        if (!best.has_value() || row.Metric < best->Metric) best = row;
    }
    if (tbl) FreeMibTable(tbl);
    return best;
}

// IPv6
bool ipv6_from_string(const char* s, IN6_ADDR& out) {
    return InetPtonA(AF_INET6, s, &out) == 1;
}

bool add_ipv6_address_on_if(const NET_LUID& ifLuid, const char* ip, UINT8 prefixLen /*обычно 128*/) {
    MIB_UNICASTIPADDRESS_ROW row{};
    InitializeUnicastIpAddressEntry(&row);
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

    if (CreateUnicastIpAddressEntry(&row) == ERROR_OBJECT_ALREADY_EXISTS)
        return SetUnicastIpAddressEntry(&row) == NO_ERROR;
    return GetLastError() == NO_ERROR;
}

bool set_if_metric_ipv6(const NET_LUID& ifLuid, ULONG metric) {
    MIB_IPINTERFACE_ROW row{};
    InitializeIpInterfaceEntry(&row);
    row.Family = AF_INET6;
    row.InterfaceLuid = ifLuid;
    if (GetIpInterfaceEntry(&row) != NO_ERROR) return false;
    row.Metric = metric;
    return SetIpInterfaceEntry(&row) == NO_ERROR;
}

bool set_if_mtu_ipv6(const NET_LUID& ifLuid, ULONG mtu) {
    MIB_IPINTERFACE_ROW row{};
    InitializeIpInterfaceEntry(&row);
    row.Family = AF_INET6;
    row.InterfaceLuid = ifLuid;
    if (GetIpInterfaceEntry(&row) != NO_ERROR) return false;
    row.NlMtu = mtu;
    return SetIpInterfaceEntry(&row) == NO_ERROR;
}

bool add_onlink_host_route6(const NET_LUID& ifLuid, const char* host, ULONG metric) {
    MIB_IPFORWARD_ROW2 r{};
    InitializeIpForwardEntry(&r);
    r.InterfaceLuid = ifLuid;
    r.DestinationPrefix.Prefix.si_family = AF_INET6;
    ipv6_from_string(host, r.DestinationPrefix.Prefix.Ipv6.sin6_addr);
    r.DestinationPrefix.PrefixLength = 128;     // host /128
    r.NextHop.si_family = AF_INET6;             // :: => on-link
    memset(&r.NextHop.Ipv6, 0, sizeof(r.NextHop.Ipv6));
    r.Metric = metric;
    r.Protocol = MIB_IPPROTO_NETMGMT;
    return CreateIpForwardEntry2(&r) == NO_ERROR || GetLastError() == ERROR_OBJECT_ALREADY_EXISTS;
}

bool add_default6_via_peer(const NET_LUID& ifLuid, const char* peer, ULONG metric) {
    MIB_IPFORWARD_ROW2 r{};
    InitializeIpForwardEntry(&r);
    r.InterfaceLuid = ifLuid;
    r.DestinationPrefix.Prefix.si_family = AF_INET6;   // ::/0
    memset(&r.DestinationPrefix.Prefix.Ipv6, 0, sizeof(r.DestinationPrefix.Prefix.Ipv6));
    r.DestinationPrefix.PrefixLength = 0;
    r.NextHop.si_family = AF_INET6;
    ipv6_from_string(peer, r.NextHop.Ipv6.sin6_addr);
    r.Metric = metric;
    r.Protocol = MIB_IPPROTO_NETMGMT;
    return CreateIpForwardEntry2(&r) == NO_ERROR || GetLastError() == ERROR_OBJECT_ALREADY_EXISTS;
}
// IPv6

// ----------------- Служебные сетевые утилиты (Win IP Helper) -----------------
bool ipv4_from_string(const char* s, IN_ADDR& out) {
    return InetPtonA(AF_INET, s, &out) == 1;
}

bool add_ipv4_address_on_if(const NET_LUID& ifLuid, const char* ip, UINT8 prefixLen /*обычно 32*/) {
    MIB_UNICASTIPADDRESS_ROW row{};
    InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid = ifLuid;
    row.Address.si_family = AF_INET;
    if (!ipv4_from_string(ip, row.Address.Ipv4.sin_addr)) return false;
    row.PrefixOrigin = IpPrefixOriginManual;
    row.SuffixOrigin = IpSuffixOriginOther;
    row.ValidLifetime = 0xFFFFFFFF; row.PreferredLifetime = 0xFFFFFFFF;
    row.DadState = IpDadStatePreferred;
    row.OnLinkPrefixLength = prefixLen;

    // Сначала пробуем создать; если уже есть — обновим.
    if (CreateUnicastIpAddressEntry(&row) == ERROR_OBJECT_ALREADY_EXISTS)
        return SetUnicastIpAddressEntry(&row) == NO_ERROR;
    return GetLastError() == NO_ERROR;
}

bool add_onlink_host_route(const NET_LUID& ifLuid, const char* host, ULONG metric) {
    MIB_IPFORWARD_ROW2 r{};
    InitializeIpForwardEntry(&r);
    r.InterfaceLuid = ifLuid;
    r.DestinationPrefix.Prefix.si_family = AF_INET;
    ipv4_from_string(host, r.DestinationPrefix.Prefix.Ipv4.sin_addr);
    r.DestinationPrefix.PrefixLength = 32;
    r.NextHop.si_family = AF_INET; // нулевой next-hop => on-link
    r.Metric = metric;
    r.Protocol = MIB_IPPROTO_NETMGMT;
    return CreateIpForwardEntry2(&r) == NO_ERROR || GetLastError() == ERROR_OBJECT_ALREADY_EXISTS;
}

std::optional<MIB_IPFORWARD_ROW2> get_best_route_to(const char* dest_ip) {
    SOCKADDR_INET dst{};
    dst.si_family = AF_INET;
    if (!ipv4_from_string(dest_ip, dst.Ipv4.sin_addr)) return std::nullopt;
    MIB_IPFORWARD_ROW2 route{};
    if (GetBestRoute2(nullptr, 0, nullptr, &dst, 0, &route, nullptr) != NO_ERROR) return std::nullopt;
    return route;
}

DWORD add_or_update_host_route_via(const char* host, const MIB_IPFORWARD_ROW2& via, ULONG metric) {
    // Нельзя пинить через "нульовой" next-hop к удалённому хосту
    if (via.DestinationPrefix.Prefix.si_family != AF_INET) return ERROR_INVALID_PARAMETER;

    bool nextHopZero = (via.NextHop.si_family == AF_INET &&
                        via.NextHop.Ipv4.sin_addr.S_un.S_addr == 0);
    if (nextHopZero) return ERROR_INVALID_PARAMETER;

    // Желаемая запись
    MIB_IPFORWARD_ROW2 desired{};
    InitializeIpForwardEntry(&desired);
    desired.InterfaceLuid = via.InterfaceLuid;
    desired.DestinationPrefix.Prefix.si_family = AF_INET;
    InetPtonA(AF_INET, host, &desired.DestinationPrefix.Prefix.Ipv4.sin_addr);
    desired.DestinationPrefix.PrefixLength = 32;
    desired.NextHop = via.NextHop;
    desired.Metric = metric;
    desired.Protocol = MIB_IPPROTO_NETMGMT;

    // Ищем существующую /32 на host
    PMIB_IPFORWARD_TABLE2 tbl = nullptr;
    if (GetIpForwardTable2(AF_INET, &tbl) == NO_ERROR) {
        for (ULONG i = 0; i < tbl->NumEntries; ++i) {
            auto &row = tbl->Table[i];
            if (row.DestinationPrefix.Prefix.si_family == AF_INET &&
                row.DestinationPrefix.PrefixLength == 32 &&
                row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr ==
                    desired.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr) {
                // апдейт на нужный интерфейс/шлюз/метрику
                row.InterfaceLuid = desired.InterfaceLuid;
                row.NextHop       = desired.NextHop;
                row.Metric        = desired.Metric;
                row.Protocol      = MIB_IPPROTO_NETMGMT;
                DWORD rc = SetIpForwardEntry2(&row);
                FreeMibTable(tbl);
                return rc;
            }
        }
        FreeMibTable(tbl);
    }
    // Создаём
    return CreateIpForwardEntry2(&desired);
}

bool set_if_metric_ipv4(const NET_LUID& ifLuid, ULONG metric /*меньше=лучше*/) {
    MIB_IPINTERFACE_ROW row{};
    InitializeIpInterfaceEntry(&row);
    row.Family = AF_INET;
    row.InterfaceLuid = ifLuid;
    if (GetIpInterfaceEntry(&row) != NO_ERROR) return false;
    row.Metric = metric;
    return SetIpInterfaceEntry(&row) == NO_ERROR;
}

bool add_default_via_peer(const NET_LUID& ifLuid, const char* peer, ULONG metric) {
    MIB_IPFORWARD_ROW2 r{};
    InitializeIpForwardEntry(&r);
    r.InterfaceLuid = ifLuid;
    r.DestinationPrefix.Prefix.si_family = AF_INET;
    r.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr = 0;
    r.DestinationPrefix.PrefixLength = 0;
    r.NextHop.si_family = AF_INET;
    ipv4_from_string(peer, r.NextHop.Ipv4.sin_addr);
    r.Metric = metric;
    r.Protocol = MIB_IPPROTO_NETMGMT;
    return CreateIpForwardEntry2(&r) == NO_ERROR || GetLastError() == ERROR_OBJECT_ALREADY_EXISTS;
}

bool set_if_mtu_ipv4(const NET_LUID& ifLuid, ULONG mtu) {
    MIB_IPINTERFACE_ROW row{};
    InitializeIpInterfaceEntry(&row);
    row.Family = AF_INET;
    row.InterfaceLuid = ifLuid;
    if (GetIpInterfaceEntry(&row) != NO_ERROR) return false;
    row.NlMtu = mtu;                       // <- ключевое
    return SetIpInterfaceEntry(&row) == NO_ERROR;
}

int ConfigureNetwork(WINTUN_ADAPTER_HANDLE adapter, const std::string& server_ip)
{
    NET_LUID luid{};
    Wintun.GetLuid(adapter, &luid);
    set_if_mtu_ipv4(luid, 1400);

    const char* LOCAL_IP = "10.8.0.2";
    const char* PEER_IP  = "10.8.0.1";

    // Назначить IPv4 10.8.0.2/32
    if (!add_ipv4_address_on_if(luid, LOCAL_IP, 32)) {
        printf("Failed to assign IPv4 on Wintun\n");
        return 1;
    }
    // On-link маршрут к пиру 10.8.0.1 (для p2p next-hop)
    add_onlink_host_route(luid, PEER_IP, 1);

    // IPv6
    const char* LOCAL6 = "fd00:dead:beef::2";
    const char* PEER6  = "fd00:dead:beef::1";

    // MTU для IPv6 такой же, как для IPv4 (чтобы не ловить blackhole)
    set_if_mtu_ipv6(luid, 1400);

    // IPv6 адрес на Wintun (точка-точка /128)
    add_ipv6_address_on_if(luid, LOCAL6, 128);

    // On-link маршрут к peer (иначе next-hop недостижим)
    add_onlink_host_route6(luid, PEER6, 1);

    // Низкая метрика интерфейса для IPv6
    set_if_metric_ipv6(luid, 1);

    // Дефолт IPv6 ::/0 через peer
    add_default6_via_peer(luid, PEER6, 1);
    // IPv6

    // Закрепить маршрут к серверу через текущий физический путь (чтобы трафик к серверу не ушёл в туннель)
    // --- ПИНУЕМ маршрут к серверу до смены дефолта ---
    auto best = get_best_route_to(server_ip.c_str());
    if (!best.has_value()) {
        auto fb = fallback_default_route_excluding(luid);
        if (fb.has_value()) best = fb;
    }

    std::optional<ULONG> server_ifindex_for_bind; // для плана Б

    if (best.has_value()) {
        DWORD rc = add_or_update_host_route_via(server_ip.c_str(), best.value(), 1);
        if (rc == NO_ERROR) {
            printf("[OK] pinned host route to %s via iface LUID=%llu\n",
                   server_ip.c_str(), (unsigned long long)best->InterfaceLuid.Value);
        } else {
            printf("[WARN] pin failed rc=%lu; will bind UDP to ifindex=%u\n",
                   rc, best->InterfaceIndex);
            server_ifindex_for_bind = best->InterfaceIndex; // план Б
        }
    } else {
        printf("[WARN] no non-tunnel route found; will bind UDP by interface later\n");
    }

    // --- ТЕПЕРЬ безопасно ставим дефолт через peer на Wintun ---
    set_if_metric_ipv4(luid, 1);
    add_default_via_peer(luid, PEER_IP, 1);

    return 0;
}
