#include "Network.hpp"

#include <cstring>
#include <cstdio>
#include <iostream>

bool is_ipv6_literal(const std::string &s) { return s.find(':') != std::string::npos; }

std::string strip_brackets(std::string s)
{
    if (!s.empty() && s.front() == '[' && s.back() == ']')
        return s.substr(1, s.size() - 2);
    return s;
}

#ifdef __linux__

// ===== LINUX =====

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>

#include <netlink/addr.h>
#include <netlink/cache.h>
#include <netlink/netlink.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>

static void die(const char *where, int err)
{
    std::fprintf(stderr, "%s: %s\n", where, nl_geterror(err));
    std::exit(EXIT_FAILURE);
}

static void warn(const char *where, int err)
{
    std::fprintf(stderr, "%s: %s (ignored)\n", where, nl_geterror(err));
}

int if_set_up(const std::string &ifname)
{
    int s = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0) return -errno;

    ifreq ifr{};
    std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname.c_str());

    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0)
    { int e = -errno; ::close(s); return e; }

    ifr.ifr_flags |= IFF_UP;

    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0)
    { int e = -errno; ::close(s); return e; }

    ::close(s);
    return 0;
}

int if_set_mtu(const std::string &ifname, int mtu)
{
    int s = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0) return -errno;

    ifreq ifr{};
    std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname.c_str());
    ifr.ifr_mtu = mtu;

    if (ioctl(s, SIOCSIFMTU, &ifr) < 0)
    { int e = -errno; ::close(s); return e; }

    ::close(s);
    return 0;
}

void flush_addrs(struct nl_sock *sk, int ifindex, int family)
{
    struct nl_cache *ac = nullptr;
    int err = rtnl_addr_alloc_cache(sk, &ac);
    if (err < 0) die("rtnl_addr_alloc_cache", err);

    for (auto *obj = nl_cache_get_first(ac); obj; obj = nl_cache_get_next(obj))
    {
        auto *a = (rtnl_addr *) obj;
        if (rtnl_addr_get_ifindex(a) != ifindex) continue;
        if (rtnl_addr_get_family(a)  != family)  continue;

        int del_err = rtnl_addr_delete(sk, a, 0);
        if (del_err < 0) warn("rtnl_addr_delete", del_err);
    }

    nl_cache_free(ac);
}

void add_addr_p2p(struct nl_sock *sk, int ifindex, int family,
                  const std::string &local_str, int prefix,
                  const std::string &peer_str)
{
    nl_addr *local = nullptr;
    nl_addr *peer  = nullptr;

    int err = nl_addr_parse(local_str.c_str(), family, &local);
    if (err < 0) die("nl_addr_parse(local)", err);
    nl_addr_set_prefixlen(local, prefix);

    err = nl_addr_parse(peer_str.c_str(), family, &peer);
    if (err < 0) die("nl_addr_parse(peer)", err);

    rtnl_addr *a = rtnl_addr_alloc();
    rtnl_addr_set_ifindex(a, ifindex);
    rtnl_addr_set_family(a, family);
    rtnl_addr_set_local(a, local);
    rtnl_addr_set_peer(a,  peer);

    if (family == AF_INET6)
        rtnl_addr_set_flags(a, IFA_F_NODAD | IFA_F_NOPREFIXROUTE);

    err = rtnl_addr_add(sk, a, NLM_F_CREATE | NLM_F_REPLACE);
    if (err < 0) die("rtnl_addr_add", err);

    rtnl_addr_put(a);
    nl_addr_put(local);
    nl_addr_put(peer);
}

std::optional<GwInfo> find_default_gw(struct nl_sock *sk, int family)
{
    struct nl_cache *rcache = nullptr;
    int err = rtnl_route_alloc_cache(sk, family, 0, &rcache);
    if (err < 0) die("rtnl_route_alloc_cache", err);

    std::optional<GwInfo> out;
    for (auto *obj = nl_cache_get_first(rcache); obj; obj = nl_cache_get_next(obj))
    {
        auto *r = (rtnl_route *) obj;
        if (rtnl_route_get_table(r) != RT_TABLE_MAIN) continue;

        nl_addr *dst = rtnl_route_get_dst(r);
        if (dst && nl_addr_get_prefixlen(dst) != 0) continue;

        int nhs = rtnl_route_get_nnexthops(r);
        if (nhs <= 0) continue;

        auto *nh = rtnl_route_nexthop_n(r, 0);
        if (!nh) continue;

        nl_addr *gw = rtnl_route_nh_get_gateway(nh);
        if (!gw) continue;

        char buf[INET6_ADDRSTRLEN];
        if (!nl_addr2str(gw, buf, sizeof(buf))) continue;

        out = GwInfo{ rtnl_route_nh_get_ifindex(nh), std::string(buf) };
        break;
    }

    nl_cache_free(rcache);
    return out;
}

std::optional<int> get_default_metric(int family)
{
    struct nl_sock *sk = nl_socket_alloc();
    if (!sk) return std::nullopt;

    if (int err = nl_connect(sk, NETLINK_ROUTE); err < 0)
    { nl_socket_free(sk); return std::nullopt; }

    struct nl_cache *rcache = nullptr;
    int err = rtnl_route_alloc_cache(sk, family, 0, &rcache);
    if (err < 0) { nl_socket_free(sk); return std::nullopt; }

    std::optional<int> metric;
    for (auto *obj = nl_cache_get_first(rcache); obj; obj = nl_cache_get_next(obj))
    {
        auto *r = (rtnl_route *) obj;
        if (rtnl_route_get_table(r) != RT_TABLE_MAIN) continue;

        nl_addr *dst = rtnl_route_get_dst(r);
        if (dst && nl_addr_get_prefixlen(dst) == 0)
        {
            int prio = rtnl_route_get_priority(r);
            if (prio < 0) prio = 100;
            metric = prio;
            break;
        }
    }

    nl_cache_free(rcache);
    nl_socket_free(sk);
    return metric;
}

void add_host_route_via_gw(struct nl_sock *sk, int family,
                           const std::string &host_ip, const GwInfo &gw)
{
    nl_addr *dst = nullptr;
    int err = nl_addr_parse(host_ip.c_str(), family, &dst);
    if (err < 0) die("nl_addr_parse(dst)", err);
    nl_addr_set_prefixlen(dst, (family == AF_INET) ? 32 : 128);

    nl_addr *gwaddr = nullptr;
    err = nl_addr_parse(gw.gw_text.c_str(), family, &gwaddr);
    if (err < 0) die("nl_addr_parse(gw)", err);

    rtnl_route *route = rtnl_route_alloc();
    rtnl_route_set_family(route, family);
    rtnl_route_set_table(route, RT_TABLE_MAIN);
    rtnl_route_set_dst(route, dst);
    rtnl_route_set_type(route, RTN_UNICAST);
    rtnl_route_set_scope(route, RT_SCOPE_UNIVERSE);
    rtnl_route_set_protocol(route, RTPROT_BOOT);

    rtnl_nexthop *nh = rtnl_route_nh_alloc();
    rtnl_route_nh_set_ifindex(nh, gw.ifindex);
    rtnl_route_nh_set_gateway(nh, gwaddr);
    rtnl_route_add_nexthop(route, nh);

    err = rtnl_route_add(sk, route, NLM_F_CREATE | NLM_F_REPLACE);
    if (err < 0) std::fprintf(stderr, "rtnl_route_add(host via gw): %s\n", nl_geterror(err));

    rtnl_route_put(route);
    nl_addr_put(dst);
    nl_addr_put(gwaddr);
}

void replace_default_via_dev(struct nl_sock *sk, int family, int oif)
{
    nl_addr *dst = nullptr;
    const char *zero = (family == AF_INET) ? "0.0.0.0" : "::";

    int err = nl_addr_parse(zero, family, &dst);
    if (err < 0) die("nl_addr_parse(0/0)", err);
    nl_addr_set_prefixlen(dst, 0);

    int metric = 5;
    if (auto cur = get_default_metric(family))
        metric = std::max(0, *cur - 10);

    rtnl_route *route = rtnl_route_alloc();
    rtnl_route_set_family(route, family);
    rtnl_route_set_table(route, RT_TABLE_MAIN);
    rtnl_route_set_dst(route, dst);
    rtnl_route_set_type(route, RTN_UNICAST);

    if (family == AF_INET)
        rtnl_route_set_scope(route, RT_SCOPE_LINK);
    else
        rtnl_route_set_scope(route, RT_SCOPE_UNIVERSE);

    rtnl_route_set_protocol(route, RTPROT_BOOT);
    rtnl_route_set_priority(route, metric);

    rtnl_nexthop *nh = rtnl_route_nh_alloc();
    rtnl_route_nh_set_ifindex(nh, oif);
    rtnl_route_add_nexthop(route, nh);

    err = rtnl_route_add(sk, route, NLM_F_CREATE | NLM_F_REPLACE);
    if (err < 0) std::fprintf(stderr, "rtnl_route_add(default dev): %s\n", nl_geterror(err));

    rtnl_route_put(route);
    nl_addr_put(dst);
}

void write_proc(const char *path, const char *data)
{
    int fd = ::open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return;
    (void) ::write(fd, data, std::strlen(data));
    ::close(fd);
}

void write_proc_if_sysctl(const std::string &ifname, const char *key, const char *value)
{
    char path[256];
    std::snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/%s", ifname.c_str(), key);
    int fd = ::open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return;
    (void) ::write(fd, value, std::strlen(value));
    ::close(fd);
}

#else

// ===== WINDOWS =====

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601 // Win7+
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <windows.h>
#include <stringapiset.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

static std::wstring utf8_to_wide(const std::string& s)
{
    if (s.empty()) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), len);
    return w;
}

static bool parse_ip(int family, const std::string& text, SOCKADDR_INET* out)
{
    std::memset(out, 0, sizeof(*out));
    out->si_family = (ADDRESS_FAMILY)family;
    if (family == AF_INET)
    {
        out->Ipv4.sin_family = AF_INET;
        return InetPtonA(AF_INET, text.c_str(), &out->Ipv4.sin_addr) == 1;
    }
    else
    {
        out->Ipv6.sin6_family = AF_INET6;
        return InetPtonA(AF_INET6, text.c_str(), &out->Ipv6.sin6_addr) == 1;
    }
}

static void zero_sockaddr(int family, SOCKADDR_INET* out)
{
    std::memset(out, 0, sizeof(*out));
    out->si_family = (ADDRESS_FAMILY)family;
    if (family == AF_INET) out->Ipv4.sin_family = AF_INET;
    else out->Ipv6.sin6_family = AF_INET6;
}

static bool alias_to_luid(const std::string& ifname, NET_LUID* luid)
{
    auto w = utf8_to_wide(ifname);
    return ConvertInterfaceAliasToLuid(w.c_str(), luid) == NO_ERROR;
}

static bool alias_to_index(const std::string& ifname, NET_IFINDEX* idx)
{
    NET_LUID luid{};
    if (!alias_to_luid(ifname, &luid)) return false;
    return ConvertInterfaceLuidToIndex(&luid, idx) == NO_ERROR;
}

int if_set_up(const std::string &ifname)
{
    NET_LUID luid{};
    if (!alias_to_luid(ifname, &luid)) return -1;

    NET_IFINDEX idx{};
    if (ConvertInterfaceLuidToIndex(&luid, &idx) != NO_ERROR) return -2;

    MIB_IFROW row{};
    row.dwIndex = idx;

    if (GetIfEntry(&row) != NO_ERROR) return -3;

    row.dwAdminStatus = MIB_IF_ADMIN_STATUS_UP; // 1
    if (SetIfEntry(&row) != NO_ERROR) return -4;

    return 0;
}

int if_set_mtu(const std::string &ifname, int mtu)
{
    NET_LUID luid{};
    if (!alias_to_luid(ifname, &luid)) return -1;

    for (int fam : {AF_INET, AF_INET6})
    {
        MIB_IPINTERFACE_ROW ipif{};
        InitializeIpInterfaceEntry(&ipif);
        ipif.Family = (ADDRESS_FAMILY)fam;
        ipif.InterfaceLuid = luid;

        if (GetIpInterfaceEntry(&ipif) != NO_ERROR) continue;
        ipif.NlMtu = mtu > 0 ? (ULONG)mtu : ipif.NlMtu;
        (void)SetIpInterfaceEntry(&ipif); // игнорируем ошибку для одного из семейств
    }
    return 0;
}

void flush_addrs_win(const std::string &ifname, int family)
{
    NET_LUID luid{};
    if (!alias_to_luid(ifname, &luid)) return;

    PMIB_UNICASTIPADDRESS_TABLE tbl = nullptr;
    if (GetUnicastIpAddressTable((ADDRESS_FAMILY)family, &tbl) != NO_ERROR) return;

    for (ULONG i = 0; i < tbl->NumEntries; ++i)
    {
        auto &row = tbl->Table[i];
        if (row.InterfaceLuid.Value != luid.Value) continue;
        // Копию, потому что Delete ожидает валидный row
        MIB_UNICASTIPADDRESS_ROW del = row;
        (void)DeleteUnicastIpAddressEntry(&del);
    }
    FreeMibTable(tbl);
}

void add_addr_p2p_win(const std::string &ifname, int family,
                      const std::string &local_str, int prefix,
                      const std::string &peer_str)
{
    NET_LUID luid{};
    if (!alias_to_luid(ifname, &luid)) throw std::runtime_error("if not found");

    // 1) Назначаем локальный /32(/128) адрес
    MIB_UNICASTIPADDRESS_ROW u{};
    InitializeUnicastIpAddressEntry(&u);
    u.InterfaceLuid = luid;
    u.Address.si_family = (ADDRESS_FAMILY)family;
    if (!parse_ip(family, local_str, &u.Address))
        throw std::runtime_error("bad local ip");

    u.PrefixOrigin = IpPrefixOriginManual;
    u.SuffixOrigin = IpSuffixOriginManual;
    u.OnLinkPrefixLength = (UINT8)prefix;
    u.ValidLifetime = 0xFFFFFFFF;   // Infinite
    u.PreferredLifetime = 0xFFFFFFFF;

    ULONG rc = CreateUnicastIpAddressEntry(&u);
    if (rc != NO_ERROR && rc != ERROR_OBJECT_ALREADY_EXISTS)
        throw std::runtime_error("CreateUnicastIpAddressEntry failed");

    // 2) Хост-маршрут к peer «на линк» (NextHop = 0)
    MIB_IPFORWARD_ROW2 fr{};
    InitializeIpForwardEntry(&fr);
    fr.InterfaceLuid = luid;
    fr.DestinationPrefix.Prefix.si_family = (ADDRESS_FAMILY)family;
    if (!parse_ip(family, peer_str, &fr.DestinationPrefix.Prefix))
        throw std::runtime_error("bad peer ip");
    fr.DestinationPrefix.PrefixLength = (family == AF_INET) ? 32 : 128;
    zero_sockaddr(family, &fr.NextHop); // on-link
    fr.Metric = 10;
    fr.Protocol = MIB_IPPROTO_NETMGMT;

    (void)CreateIpForwardEntry2(&fr); // если уже есть — ок
}

std::optional<GwInfo> find_default_gw_win(int family)
{
    PMIB_IPFORWARD_TABLE2 tbl = nullptr;
    if (GetIpForwardTable2((ADDRESS_FAMILY)family, &tbl) != NO_ERROR)
        return std::nullopt;

    std::optional<GwInfo> out;
    ULONG bestMetric = UINT_MAX;
    for (ULONG i = 0; i < tbl->NumEntries; ++i)
    {
        const auto &r = tbl->Table[i];
        if (r.DestinationPrefix.PrefixLength != 0) continue;

        // Ищем наименьшую метрику
        if (r.Metric < bestMetric)
        {
            char buf[INET6_ADDRSTRLEN] = {0};
            if (family == AF_INET)
                InetNtopA(AF_INET, (void*)&r.NextHop.Ipv4.sin_addr, buf, sizeof(buf));
            else
                InetNtopA(AF_INET6, (void*)&r.NextHop.Ipv6.sin6_addr, buf, sizeof(buf));

            NET_IFINDEX idx{};
            ConvertInterfaceLuidToIndex((NET_LUID*)&r.InterfaceLuid, &idx);
            out = GwInfo{ (int)idx, std::string(buf) };
            bestMetric = r.Metric;
        }
    }
    FreeMibTable(tbl);
    return out;
}

std::optional<int> get_default_metric(int family)
{
    PMIB_IPFORWARD_TABLE2 tbl = nullptr;
    if (GetIpForwardTable2((ADDRESS_FAMILY)family, &tbl) != NO_ERROR)
        return std::nullopt;

    std::optional<int> metric;
    ULONG bestMetric = UINT_MAX;
    for (ULONG i = 0; i < tbl->NumEntries; ++i)
    {
        const auto &r = tbl->Table[i];
        if (r.DestinationPrefix.PrefixLength != 0) continue;
        if (r.Metric < bestMetric) { bestMetric = r.Metric; metric = (int)bestMetric; }
    }
    FreeMibTable(tbl);
    return metric;
}

void add_host_route_via_gw_win(int family,
                               const std::string &host_ip,
                               const GwInfo &gw)
{
    MIB_IPFORWARD_ROW2 fr{};
    InitializeIpForwardEntry(&fr);

    // ifindex -> luid
    NET_LUID luid{};
    if (ConvertInterfaceIndexToLuid((NET_IFINDEX)gw.ifindex, &luid) != NO_ERROR)
        return;
    fr.InterfaceLuid = luid;

    fr.DestinationPrefix.Prefix.si_family = (ADDRESS_FAMILY)family;
    if (!parse_ip(family, host_ip, &fr.DestinationPrefix.Prefix)) return;
    fr.DestinationPrefix.PrefixLength = (family == AF_INET) ? 32 : 128;

    fr.NextHop.si_family = (ADDRESS_FAMILY)family;
    if (!parse_ip(family, gw.gw_text, &fr.NextHop)) return;

    fr.Metric = 5;
    fr.Protocol = MIB_IPPROTO_NETMGMT;
    (void)CreateIpForwardEntry2(&fr);
}

void add_split_default_onlink_win(const std::string& ifname) {
    NET_LUID luid{}; if (!alias_to_luid(ifname, &luid)) return;

    for (auto p : { std::pair<const char*,UINT8>{"0.0.0.0",1},
                    std::pair<const char*,UINT8>{"128.0.0.0",1} })
    {
        MIB_IPFORWARD_ROW2 fr{}; InitializeIpForwardEntry(&fr);
        fr.InterfaceLuid = luid;
        fr.DestinationPrefix.Prefix.si_family = AF_INET;
        InetPtonA(AF_INET, p.first, &fr.DestinationPrefix.Prefix.Ipv4.sin_addr);
        fr.DestinationPrefix.PrefixLength = p.second;

        // ВАЖНО: on-link (без шлюза)
        zero_sockaddr(AF_INET, &fr.NextHop);

        fr.Metric   = 5;
        fr.Protocol = MIB_IPPROTO_NETMGMT;
        (void)CreateIpForwardEntry2(&fr);
    }
}

void set_interface_metric_win(const std::string &ifname, int family, unsigned metric)
{
    NET_LUID luid{}; if (!alias_to_luid(ifname, &luid)) return;

    MIB_IPINTERFACE_ROW ipif{};
    InitializeIpInterfaceEntry(&ipif);
    ipif.Family = (ADDRESS_FAMILY)family;
    ipif.InterfaceLuid = luid;

    if (GetIpInterfaceEntry(&ipif) != NO_ERROR) return;
    ipif.UseAutomaticMetric = FALSE;
    ipif.Metric = metric; // сделаем 1
    (void)SetIpInterfaceEntry(&ipif);
}

void replace_default_via_dev_win(int family, const std::string &ifname, const std::string &peer_str)
{
    NET_LUID luid{}; if (!alias_to_luid(ifname, &luid)) return;

    ULONG metric = 5;
    if (auto cur = get_default_metric(family))
        metric = (ULONG)std::max(0, *cur - 10);

    MIB_IPFORWARD_ROW2 fr{}; InitializeIpForwardEntry(&fr);
    fr.InterfaceLuid = luid;

    fr.DestinationPrefix.Prefix.si_family = (ADDRESS_FAMILY)family;
    if (family == AF_INET) fr.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
    else                   fr.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
    fr.DestinationPrefix.PrefixLength = 0;

    // ВАЖНО: дефолт через peer (а не on-link)
    if (!parse_ip(family, peer_str, &fr.NextHop)) return;

    fr.Metric   = metric;
    fr.Protocol = MIB_IPPROTO_NETMGMT;
    (void)CreateIpForwardEntry2(&fr);
}


#endif // _WIN32 / __linux__
