#pragma once

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>

#include <netlink/netlink.h>
#include <netlink/addr.h>
#include <netlink/cache.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <optional>
#include <iostream>

static void die(const char *where, int err)
{
    std::fprintf(stderr, "%s: %s\n",
                 where, nl_geterror(err));
    std::exit(EXIT_FAILURE);
}

static void warn(const char *where, int err)
{
    std::fprintf(stderr, "%s: %s (ignored)\n",
                 where, nl_geterror(err));
}

static bool is_ipv6_literal(const std::string &s)
{ return s.find(':') != std::string::npos; }

static std::string strip_brackets(std::string s)
{
    if (!s.empty() && s.front() == '[' && s.back() == ']')
    { return s.substr(1, s.size() - 2); }
    return s;
}

// --- ioctl helpers ---
static int if_set_up(const std::string &ifname)
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

static int if_set_mtu(const std::string &ifname, int mtu)
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

// --- addr helpers ---
static void flush_addrs(struct nl_sock *sk, int ifindex, int family)
{
    struct nl_cache *ac = nullptr;
    int err = rtnl_addr_alloc_cache(sk, &ac);
    if (err < 0) die("rtnl_addr_alloc_cache", err);

    for (auto *obj = nl_cache_get_first(ac);
         obj;
         obj = nl_cache_get_next(obj))
    {
        auto *a = (rtnl_addr *) obj;
        if (rtnl_addr_get_ifindex(a) != ifindex) continue;
        if (rtnl_addr_get_family(a)  != family)  continue;

        int del_err = rtnl_addr_delete(sk, a, 0);
        if (del_err < 0) warn("rtnl_addr_delete", del_err);
    }

    nl_cache_free(ac);
}

static void add_addr_p2p(struct nl_sock *sk, int ifindex, int family,
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
    { rtnl_addr_set_flags(a, IFA_F_NODAD | IFA_F_NOPREFIXROUTE); }

    err = rtnl_addr_add(sk, a, NLM_F_CREATE | NLM_F_REPLACE);
    if (err < 0) die("rtnl_addr_add", err);

    rtnl_addr_put(a);
    nl_addr_put(local);
    nl_addr_put(peer);
}

// --- find default GW ---
struct GwInfo
{
    int         ifindex;
    std::string gw_text;
};

static std::optional<GwInfo> find_default_gw(struct nl_sock *sk, int family)
{
    struct nl_cache *rcache = nullptr;
    int err = rtnl_route_alloc_cache(sk, family, 0, &rcache);
    if (err < 0) die("rtnl_route_alloc_cache", err);

    std::optional<GwInfo> out;

    for (auto *obj = nl_cache_get_first(rcache);
         obj;
         obj = nl_cache_get_next(obj))
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

        out = GwInfo{
                rtnl_route_nh_get_ifindex(nh),
                std::string(buf)
        };
        break;
    }

    nl_cache_free(rcache);
    return out;
}

// --- get current default metric ---
static std::optional<int> get_default_metric(struct nl_sock *sk, int family)
{
    struct nl_cache *rcache = nullptr;
    int err = rtnl_route_alloc_cache(sk, family, 0, &rcache);
    if (err < 0) die("rtnl_route_alloc_cache", err);

    std::optional<int> metric;

    for (auto *obj = nl_cache_get_first(rcache);
         obj;
         obj = nl_cache_get_next(obj))
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
    return metric;
}

// --- routes ---
static void add_host_route_via_gw(struct nl_sock *sk, int family,
                      const std::string &host_ip,
                      const GwInfo &gw)
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
    if (err < 0) warn("rtnl_route_add(host via gw)", err);

    rtnl_route_put(route);
    nl_addr_put(dst);
    nl_addr_put(gwaddr);
}

static void replace_default_via_dev(struct nl_sock *sk, int family, int oif)
{
    nl_addr *dst = nullptr;
    const char *zero = (family == AF_INET) ? "0.0.0.0" : "::";

    int err = nl_addr_parse(zero, family, &dst);
    if (err < 0) die("nl_addr_parse(0/0)", err);
    nl_addr_set_prefixlen(dst, 0);

    int metric = 5;
    if (auto cur = get_default_metric(sk, family))
    { metric = std::max(0, *cur - 10); }

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
    if (err < 0) warn("rtnl_route_add(default dev)", err);

    rtnl_route_put(route);
    nl_addr_put(dst);
}

static void write_proc(const char *path, const char *data)
{
    int fd = ::open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return;
    (void) ::write(fd, data, std::strlen(data));
    ::close(fd);
}

static void write_proc_if_sysctl(const std::string &ifname,
                     const char       *key,
                     const char       *value)
{
    char path[256];
    std::snprintf(path, sizeof(path),
                  "/proc/sys/net/ipv6/conf/%s/%s",
                  ifname.c_str(), key);
    int fd = ::open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return;
    (void) ::write(fd, value, std::strlen(value));
    ::close(fd);
}
