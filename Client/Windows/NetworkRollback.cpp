#include "NetworkRollback.hpp"
#include <vector>
#include <cstring>
#include <cstdio>

namespace {

bool load_ip_if_row(ADDRESS_FAMILY fam, const NET_LUID& luid,
                    MIB_IPINTERFACE_ROW& row) {
    InitializeIpInterfaceEntry(&row);
    row.Family = fam;
    row.InterfaceLuid = luid;
    return GetIpInterfaceEntry(&row) == NO_ERROR;
}

bool save_iface(ADDRESS_FAMILY fam, const NET_LUID& luid,
                BOOL& autoMetric, ULONG& metric, ULONG& mtu, bool& have) {
    MIB_IPINTERFACE_ROW row{};
    if (!load_ip_if_row(fam, luid, row)) return false;
    autoMetric = row.UseAutomaticMetric;
    metric     = row.Metric;
    mtu        = row.NlMtu;
    have       = true;
    return true;
}

bool restore_iface(ADDRESS_FAMILY fam, const NET_LUID& luid,
                   BOOL autoMetric, ULONG metric, ULONG mtu) {
    MIB_IPINTERFACE_ROW row{};
    if (!load_ip_if_row(fam, luid, row)) return false;

    row.UseAutomaticMetric = autoMetric;
    row.Metric             = metric;
    DWORD rc1 = SetIpInterfaceEntry(&row);
    if (rc1 != NO_ERROR && rc1 != ERROR_INVALID_PARAMETER) {
        std::printf("[WARN] Restore metric fam=%d rc=%lu\n", fam, rc1);
    }

    // Отдельным вызовом MTU (чтобы не затирать другие поля)
    if (!load_ip_if_row(fam, luid, row)) return rc1 == NO_ERROR;
    row.NlMtu = mtu;
    DWORD rc2 = SetIpInterfaceEntry(&row);
    if (rc2 != NO_ERROR && rc2 != ERROR_INVALID_PARAMETER) {
        std::printf("[WARN] Restore MTU fam=%d rc=%lu\n", fam, rc2);
    }
    return (rc1 == NO_ERROR || rc1 == ERROR_INVALID_PARAMETER) &&
           (rc2 == NO_ERROR || rc2 == ERROR_INVALID_PARAMETER);
}

bool same_v4(const IN_ADDR& a, const IN_ADDR& b) {
    return a.S_un.S_addr == b.S_un.S_addr;
}
bool same_v6(const IN6_ADDR& a, const IN6_ADDR& b) {
    return std::memcmp(&a, &b, sizeof(IN6_ADDR)) == 0;
}

// Удалить маршруты из таблицы по предикату
template<class Pred>
bool delete_routes_where(ADDRESS_FAMILY fam, Pred pred) {
    PMIB_IPFORWARD_TABLE2 tbl = nullptr;
    DWORD rc = GetIpForwardTable2(fam, &tbl);
    if (rc != NO_ERROR) return false;

    std::vector<MIB_IPFORWARD_ROW2> toDel;
    toDel.reserve(tbl->NumEntries);
    for (ULONG i = 0; i < tbl->NumEntries; ++i) {
        const auto& row = tbl->Table[i];
        if (pred(row)) toDel.push_back(row);
    }
    FreeMibTable(tbl);

    bool ok = true;
    for (auto& r : toDel) {
        DWORD rc2 = DeleteIpForwardEntry2(&r);
        if (rc2 != NO_ERROR) {
            // На старых сборках это иногда 1168/87 — ничего страшного.
            std::printf("[WARN] DeleteIpForwardEntry2 fam=%d rc=%lu\n", fam, rc2);
            ok = false;
        }
    }
    return ok;
}

} // namespace

namespace netrb {

bool CaptureBaseline(const NET_LUID& ifLuid, Baseline& out) noexcept {
    out = {};
    out.luid = ifLuid;

    bool okv4 = save_iface(AF_INET,  ifLuid, out.v4AutoMetric, out.v4Metric, out.v4Mtu, out.haveV4);
    bool okv6 = save_iface(AF_INET6, ifLuid, out.v6AutoMetric, out.v6Metric, out.v6Mtu, out.haveV6);
    return okv4 || okv6;
}

bool RestoreBaseline(const Baseline& b) noexcept {
    bool ok = true;
    if (b.haveV4) ok &= restore_iface(AF_INET,  b.luid, b.v4AutoMetric, b.v4Metric, b.v4Mtu);
    if (b.haveV6) ok &= restore_iface(AF_INET6, b.luid, b.v6AutoMetric, b.v6Metric, b.v6Mtu);
    return ok;
}

bool RemoveSplitDefaults(const NET_LUID& ifLuid) noexcept {
    // IPv4: 0.0.0.0/1 и 128.0.0.0/1 на нашем интерфейсе и созданные нами (NETMGMT)
    bool ok4 = delete_routes_where(AF_INET,  [&](const MIB_IPFORWARD_ROW2& r){
        if (r.InterfaceLuid.Value != ifLuid.Value) return false;
        if (r.Protocol != MIB_IPPROTO_NETMGMT)     return false;
        if (r.DestinationPrefix.Prefix.si_family != AF_INET) return false;
        if (r.DestinationPrefix.PrefixLength != 1) return false;
        IN_ADDR zero{}, one28{};
        InetPtonA(AF_INET, "0.0.0.0",   &zero);
        InetPtonA(AF_INET, "128.0.0.0", &one28);
        const auto& dst = r.DestinationPrefix.Prefix.Ipv4.sin_addr;
        return same_v4(dst, zero) || same_v4(dst, one28);
    });

    // IPv6: ::/1 и 8000::/1 на нашем интерфейсе и созданные нами (NETMGMT)
    bool ok6 = delete_routes_where(AF_INET6, [&](const MIB_IPFORWARD_ROW2& r){
        if (r.InterfaceLuid.Value != ifLuid.Value) return false;
        if (r.Protocol != MIB_IPPROTO_NETMGMT)     return false;
        if (r.DestinationPrefix.Prefix.si_family != AF_INET6) return false;
        if (r.DestinationPrefix.PrefixLength != 1) return false;
        IN6_ADDR zero6{}, eight6{};
        InetPtonA(AF_INET6, "::",     &zero6);
        InetPtonA(AF_INET6, "8000::", &eight6);
        const auto& dst = r.DestinationPrefix.Prefix.Ipv6.sin6_addr;
        return same_v6(dst, zero6) || same_v6(dst, eight6);
    });

    return ok4 || ok6;
}

bool RemovePinnedRouteToServer(const char* serverIp) noexcept {
    if (!serverIp || !*serverIp) return false;

    // v4?
    IN_ADDR  dst4{};
    IN6_ADDR dst6{};
    if (InetPtonA(AF_INET, serverIp, &dst4) == 1) {
        // Удаляем /32 с нашим протоколом
        return delete_routes_where(AF_INET, [&](const MIB_IPFORWARD_ROW2& r){
            if (r.Protocol != MIB_IPPROTO_NETMGMT) return false;
            if (r.DestinationPrefix.Prefix.si_family != AF_INET) return false;
            if (r.DestinationPrefix.PrefixLength != 32) return false;
            return same_v4(r.DestinationPrefix.Prefix.Ipv4.sin_addr, dst4);
        });
    }

    if (InetPtonA(AF_INET6, serverIp, &dst6) == 1) {
        // Удаляем /128 с нашим протоколом
        return delete_routes_where(AF_INET6, [&](const MIB_IPFORWARD_ROW2& r){
            if (r.Protocol != MIB_IPPROTO_NETMGMT) return false;
            if (r.DestinationPrefix.Prefix.si_family != AF_INET6) return false;
            if (r.DestinationPrefix.PrefixLength != 128) return false;
            return same_v6(r.DestinationPrefix.Prefix.Ipv6.sin6_addr, dst6);
        });
    }

    // Некорректный IP
    return false;
}

bool RollbackAll(const Baseline& b, const char* serverIp) noexcept {
    // Порядок: сначала снять /1 (чтобы восстановить оригинальные дефолты),
    // затем убрать пин до сервера, затем вернуть метрики/MTU.
    bool ok = true;
    ok &= RemoveSplitDefaults(b.luid);
    if (serverIp && *serverIp) ok &= RemovePinnedRouteToServer(serverIp);
    ok &= RestoreBaseline(b);
    return ok;
}

} // namespace netrb
