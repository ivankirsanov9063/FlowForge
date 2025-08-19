// NetworkRollback.cpp — реализация RAII-отката сетевых правок (Windows)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <iphlpapi.h>
#include <netioapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#include "NetworkRollback.hpp"
#include "Logger.hpp"

#include <vector>
#include <cstring>
#include <cstdio>
#include <utility>

// ---------- helpers ----------

namespace
{
    bool load_ip_if_row(ADDRESS_FAMILY fam,
                        const NET_LUID &luid,
                        MIB_IPINTERFACE_ROW &row)
    {
        InitializeIpInterfaceEntry(&row);
        row.Family = fam;
        row.InterfaceLuid = luid;
        return GetIpInterfaceEntry(&row) == NO_ERROR;
    }

    bool save_iface(ADDRESS_FAMILY fam,
                    const NET_LUID &luid,
                    BOOL &autoMetric,
                    ULONG &metric,
                    ULONG &mtu,
                    bool &have)
    {
        MIB_IPINTERFACE_ROW row{};
        if (!load_ip_if_row(fam, luid, row)) return false;
        autoMetric = row.UseAutomaticMetric;
        metric     = row.Metric;
        mtu        = row.NlMtu;
        have       = true;
        LOGD("networkrollback") << "save_iface: fam=" << fam
                                << " autoMetric=" << (autoMetric ? 1 : 0)
                                << " metric=" << metric
                                << " mtu=" << mtu;
        return true;
    }

    // Возвращает NO_ERROR/ERROR_INVALID_PARAMETER как «нормально» (совместимо со старым кодом).
    bool restore_iface(ADDRESS_FAMILY fam,
                       const NET_LUID &luid,
                       BOOL autoMetric,
                       ULONG metric,
                       ULONG mtu)
    {
        MIB_IPINTERFACE_ROW row{};
        if (!load_ip_if_row(fam, luid, row)) return false;

        row.UseAutomaticMetric = autoMetric;
        row.Metric             = metric;
        DWORD rc1 = SetIpInterfaceEntry(&row);
        if (rc1 != NO_ERROR && rc1 != ERROR_INVALID_PARAMETER)
        {
            LOGW("networkrollback") << "Restore metric fam=" << fam << " rc=" << rc1;
        }

        if (!load_ip_if_row(fam, luid, row)) return rc1 == NO_ERROR;
        row.NlMtu = mtu;
        DWORD rc2 = SetIpInterfaceEntry(&row);
        if (rc2 != NO_ERROR && rc2 != ERROR_INVALID_PARAMETER)
        {
            LOGW("networkrollback") << "Restore MTU fam=" << fam << " rc=" << rc2;
        }

        const bool ok = (rc1 == NO_ERROR || rc1 == ERROR_INVALID_PARAMETER) &&
                        (rc2 == NO_ERROR || rc2 == ERROR_INVALID_PARAMETER);
        LOGD("networkrollback") << "restore_iface: fam=" << fam << " ok=" << ok;
        return ok;
    }

    bool same_v4(const IN_ADDR &a,
                 const IN_ADDR &b)
    {
        return a.S_un.S_addr == b.S_un.S_addr;
    }

    bool same_v6(const IN6_ADDR &a,
                 const IN6_ADDR &b)
    {
        return std::memcmp(&a, &b, sizeof(IN6_ADDR)) == 0;
    }

    template <class Pred>
    bool delete_routes_where(ADDRESS_FAMILY fam,
                             Pred pred)
    {
        PMIB_IPFORWARD_TABLE2 tbl = nullptr;
        DWORD rc = GetIpForwardTable2(fam, &tbl);
        if (rc != NO_ERROR)
        {
            LOGE("networkrollback") << "GetIpForwardTable2 failed rc=" << rc << " fam=" << fam;
            return false;
        }

        std::vector<MIB_IPFORWARD_ROW2> toDel;
        toDel.reserve(tbl->NumEntries);
        for (ULONG i = 0; i < tbl->NumEntries; ++i)
        {
            const auto &row = tbl->Table[i];
            if (pred(row)) toDel.push_back(row);
        }
        FreeMibTable(tbl);

        bool ok = true;
        for (auto &r : toDel)
        {
            DWORD rc2 = DeleteIpForwardEntry2(&r);
            if (rc2 != NO_ERROR)
            {
                // На старых сборках это иногда 1168/87 — логируем, но считаем ошибкой операции.
                LOGW("networkrollback") << "DeleteIpForwardEntry2 fam=" << fam << " rc=" << rc2;
                ok = false;
            }
        }
        LOGD("networkrollback") << "delete_routes_where: fam=" << fam
                                << " removed=" << toDel.size() << " ok=" << ok;
        return ok;
    }
} // namespace

// ---------- NetworkRollback ----------

NetworkRollback::NetworkRollback(const NET_LUID &if_luid,
                                 const std::string &server_ip)
    : server_ip_(server_ip)
{
    snap_.luid = if_luid;
    LOGI("networkrollback") << "Construct: capture baseline (IfLuid=" << snap_.luid.Value
                            << ") server=" << server_ip_;
    CaptureBaseline_();
    LOGD("networkrollback") << "Baseline captured";
}

NetworkRollback::~NetworkRollback()
{
    try
    {
        LOGD("networkrollback") << "Destructor -> Revert()";
        Revert();
        LOGT("networkrollback") << "Destructor: revert completed";
    }
    catch (...)
    {
        // деструктор не бросает
        LOGW("networkrollback") << "Destructor: swallow exception from Revert()";
    }
}

NetworkRollback::NetworkRollback(NetworkRollback &&other) noexcept
{
    LOGT("networkrollback") << "Move-ctor";
    *this = std::move(other);
}

NetworkRollback &NetworkRollback::operator=(NetworkRollback &&other) noexcept
{
    if (this != &other)
    {
        LOGT("networkrollback") << "Move-assign";
        try { Revert(); } catch (...) { LOGW("networkrollback") << "Move-assign: Revert() threw (swallowed)"; }

        snap_      = other.snap_;
        server_ip_ = std::move(other.server_ip_);
        captured_  = other.captured_;

        other.captured_ = false;
        other.snap_     = Snapshot{};
        other.server_ip_.clear();
    }
    return *this;
}

void NetworkRollback::SetServerIp(const std::string &server_ip)
{
    LOGD("networkrollback") << "SetServerIp: " << server_ip;
    server_ip_ = server_ip;
}

bool NetworkRollback::HasBaseline() const noexcept
{
    return captured_;
}

void NetworkRollback::CaptureBaseline_()
{
    LOGD("networkrollback") << "CaptureBaseline_: begin";
    bool okv4 = save_iface(AF_INET,  snap_.luid, snap_.v4_auto_metric, snap_.v4_metric, snap_.v4_mtu, snap_.have_v4);
    bool okv6 = save_iface(AF_INET6, snap_.luid, snap_.v6_auto_metric, snap_.v6_metric, snap_.v6_mtu, snap_.have_v6);
    if (!okv4 && !okv6)
    {
        LOGE("networkrollback") << "CaptureBaseline_: failed (v4/v6)";
        throw std::runtime_error("NetworkRollback: failed to capture baseline (v4/v6)");
    }
    captured_ = true;
    LOGD("networkrollback") << "CaptureBaseline_: ok v4=" << okv4 << " v6=" << okv6;
}

void NetworkRollback::RemoveSplitDefaults_() const
{
    LOGD("networkrollback") << "RemoveSplitDefaults_: begin";
    // IPv4: 0.0.0.0/1 и 128.0.0.0/1 на нашем интерфейсе, Protocol=NETMGMT
    const bool ok4 = delete_routes_where(AF_INET, [&](const MIB_IPFORWARD_ROW2 &r)
    {
        if (r.InterfaceLuid.Value != snap_.luid.Value)       return false;
        if (r.Protocol != MIB_IPPROTO_NETMGMT)               return false;
        if (r.DestinationPrefix.Prefix.si_family != AF_INET) return false;
        if (r.DestinationPrefix.PrefixLength != 1)           return false;

        IN_ADDR zero{}, one28{};
        InetPtonA(AF_INET, "0.0.0.0",   &zero);
        InetPtonA(AF_INET, "128.0.0.0", &one28);

        const auto &dst = r.DestinationPrefix.Prefix.Ipv4.sin_addr;
        return same_v4(dst, zero) || same_v4(dst, one28);
    });

    // IPv6: ::/1 и 8000::/1 на нашем интерфейсе, Protocol=NETMGMT
    const bool ok6 = delete_routes_where(AF_INET6, [&](const MIB_IPFORWARD_ROW2 &r)
    {
        if (r.InterfaceLuid.Value != snap_.luid.Value)         return false;
        if (r.Protocol != MIB_IPPROTO_NETMGMT)                 return false;
        if (r.DestinationPrefix.Prefix.si_family != AF_INET6)  return false;
        if (r.DestinationPrefix.PrefixLength != 1)             return false;

        IN6_ADDR zero6{}, eight6{};
        InetPtonA(AF_INET6, "::",     &zero6);
        InetPtonA(AF_INET6, "8000::", &eight6);

        const auto &dst = r.DestinationPrefix.Prefix.Ipv6.sin6_addr;
        return same_v6(dst, zero6) || same_v6(dst, eight6);
    });

    if (!ok4 && !ok6)
    {
        LOGE("networkrollback") << "RemoveSplitDefaults_: failed (v4 & v6)";
        throw std::runtime_error("NetworkRollback: failed to remove split-default routes");
    }
    LOGI("networkrollback") << "RemoveSplitDefaults_: ok v4=" << ok4 << " v6=" << ok6;
}

void NetworkRollback::RemovePinnedRouteToServer_() const
{
    if (server_ip_.empty())
    {
        LOGT("networkrollback") << "RemovePinnedRouteToServer_: server_ip empty (skip)";
        return; // ничего не делаем
    }

    LOGD("networkrollback") << "RemovePinnedRouteToServer_: server_ip=" << server_ip_;

    IN_ADDR  dst4{};
    IN6_ADDR dst6{};

    if (InetPtonA(AF_INET, server_ip_.c_str(), &dst4) == 1)
    {
        const bool ok4 = delete_routes_where(AF_INET, [&](const MIB_IPFORWARD_ROW2 &r)
        {
            if (r.Protocol != MIB_IPPROTO_NETMGMT)               return false;
            if (r.DestinationPrefix.Prefix.si_family != AF_INET) return false;
            if (r.DestinationPrefix.PrefixLength != 32)          return false;
            return same_v4(r.DestinationPrefix.Prefix.Ipv4.sin_addr, dst4);
        });
        if (!ok4)
        {
            LOGE("networkrollback") << "RemovePinnedRouteToServer_: IPv4 delete failed";
            throw std::runtime_error("NetworkRollback: failed to remove pinned IPv4 route");
        }
        LOGI("networkrollback") << "RemovePinnedRouteToServer_: IPv4 route removed";
        return;
    }

    if (InetPtonA(AF_INET6, server_ip_.c_str(), &dst6) == 1)
    {
        const bool ok6 = delete_routes_where(AF_INET6, [&](const MIB_IPFORWARD_ROW2 &r)
        {
            if (r.Protocol != MIB_IPPROTO_NETMGMT)                 return false;
            if (r.DestinationPrefix.Prefix.si_family != AF_INET6)  return false;
            if (r.DestinationPrefix.PrefixLength != 128)           return false;
            return same_v6(r.DestinationPrefix.Prefix.Ipv6.sin6_addr, dst6);
        });
        if (!ok6)
        {
            LOGE("networkrollback") << "RemovePinnedRouteToServer_: IPv6 delete failed";
            throw std::runtime_error("NetworkRollback: failed to remove pinned IPv6 route");
        }
        LOGI("networkrollback") << "RemovePinnedRouteToServer_: IPv6 route removed";
        return;
    }

    LOGE("networkrollback") << "RemovePinnedRouteToServer_: server_ip invalid";
    throw std::invalid_argument("NetworkRollback: server_ip is not a valid IPv4/IPv6 address");
}

void NetworkRollback::RestoreBaseline_() const
{
    LOGD("networkrollback") << "RestoreBaseline_: begin";
    bool ok = true;
    if (snap_.have_v4) ok &= restore_iface(AF_INET,  snap_.luid, snap_.v4_auto_metric, snap_.v4_metric, snap_.v4_mtu);
    if (snap_.have_v6) ok &= restore_iface(AF_INET6, snap_.luid, snap_.v6_auto_metric, snap_.v6_metric, snap_.v6_mtu);
    if (!ok)
    {
        LOGE("networkrollback") << "RestoreBaseline_: failed";
        throw std::runtime_error("NetworkRollback: failed to restore interface metrics/mtu");
    }
    LOGI("networkrollback") << "RestoreBaseline_: ok";
}

void NetworkRollback::Revert()
{
    if (!captured_)
    {
        LOGE("networkrollback") << "Revert without baseline";
        throw std::logic_error("NetworkRollback::Revert called without baseline");
    }

    LOGI("networkrollback") << "Revert: begin";
    bool error = false;

    try { RemoveSplitDefaults_(); }       catch (...) { LOGE("networkrollback") << "Revert: RemoveSplitDefaults_ failed"; error = true; }
    try { RemovePinnedRouteToServer_(); } catch (...) { LOGE("networkrollback") << "Revert: RemovePinnedRouteToServer_ failed"; error = true; }
    try { RestoreBaseline_(); }           catch (...) { LOGE("networkrollback") << "Revert: RestoreBaseline_ failed"; error = true; }

    // Повторно использовать нельзя — считаем, что baseline отработал.
    captured_ = false;

    if (error)
    {
        LOGE("networkrollback") << "Revert: one or more operations failed";
        throw std::runtime_error("NetworkRollback::Revert: one or more operations failed");
    }
    LOGI("networkrollback") << "Revert: done";
}
