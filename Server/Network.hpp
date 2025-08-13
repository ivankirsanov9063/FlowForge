// Server/Network.hpp
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <iostream>
#include <cstring>
#include <cerrno>
#include <fstream>

#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/cache.h>
#include <netlink/addr.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/route/nexthop.h>

#include <nftables/libnftables.h>

namespace NetConfig
{
    struct CidrV4
    {
        std::uint32_t addr_be;
        std::uint8_t  prefix;
    };

    struct CidrV6
    {
        std::array<std::uint8_t, 16> addr;
        std::uint8_t                 prefix;
    };

    struct Params
    {
        int mtu = 1400;

        CidrV4       v4_local   { inet_addr("10.8.0.1"), 32 };
        std::uint32_t v4_peer_be = inet_addr("10.8.0.2");

        CidrV6 v6_local {
                { 0xfd, 0x00, 0xde, 0xad, 0xbe, 0xef,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x01 },
                128
        };

        std::array<std::uint8_t, 16> v6_peer {
                { 0xfd, 0x00, 0xde, 0xad, 0xbe, 0xef,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x02 }
        };

        std::string nat44_src = "10.8.0.0/24";
        std::string nat66_src = "fd00:dead:beef::/64";
    };

    inline bool write_sysctl(const char *path,
                 const char *val)
    {
        int fd = ::open(path, O_WRONLY | O_CLOEXEC);
        if (fd < 0) return false;

        const ssize_t need = static_cast<ssize_t>(std::strlen(val));
        const ssize_t n    = ::write(fd, val, need);
        ::close(fd);

        return n == need;
    }

    inline bool write_if_sysctl(const std::string &ifname,
                    const char        *key,
                    const char        *val)
    {
        char path[256];
        std::snprintf(path, sizeof(path),
                      "/proc/sys/net/ipv6/conf/%s/%s",
                      ifname.c_str(), key);

        int fd = ::open(path, O_WRONLY | O_CLOEXEC);
        if (fd < 0) return false;

        const ssize_t need = static_cast<ssize_t>(std::strlen(val));
        const ssize_t n    = ::write(fd, val, need);
        ::close(fd);

        return n == need;
    }

    inline nl_sock *nl_connect_route()
    {
        nl_sock *sk = nl_socket_alloc();
        if (!sk) return nullptr;

        if (nl_connect(sk, NETLINK_ROUTE) < 0)
        {
            nl_socket_free(sk);
            return nullptr;
        }
        return sk;
    }

    inline bool link_set_up_and_mtu(nl_sock *sk,
                        int      ifindex,
                        int      mtu)
    {
        rtnl_link *link = rtnl_link_alloc();
        if (!link) return false;

        rtnl_link_set_ifindex(link, ifindex);
        rtnl_link_set_mtu(link, static_cast<unsigned int>(mtu));
        rtnl_link_set_flags(link, IFF_UP);

        const int rc = rtnl_link_change(sk, link, link, 0);
        rtnl_link_put(link);
        return rc == 0;
    }
    inline bool addr_flush_all(nl_sock *sk,
                   int      ifindex)
    {
        nl_cache *cache = nullptr;
        if (rtnl_addr_alloc_cache(sk, &cache) < 0) return false;

        std::vector<rtnl_addr *> to_del;

        for (nl_object *it = nl_cache_get_first(cache);
             it;
             it = nl_cache_get_next(it))
        {
            auto *a = reinterpret_cast<rtnl_addr *>(it);
            if (rtnl_addr_get_ifindex(a) == ifindex)
            {
                nl_object_get(it);
                to_del.push_back(a);
            }
        }

        bool ok = true;
        for (auto *a : to_del)
        {
            if (rtnl_addr_delete(sk, a, 0) < 0) ok = false;
            rtnl_addr_put(a);
        }

        nl_cache_free(cache);
        return ok;
    }

    inline bool addr_add_v4_p2p(nl_sock    *sk,
                    int         ifindex,
                    std::uint32_t local_be,
                    std::uint32_t peer_be,
                    std::uint8_t  prefix)
    {
        rtnl_addr *a = rtnl_addr_alloc();
        if (!a) return false;
        rtnl_addr_set_ifindex(a, ifindex);

        nl_addr *l = nl_addr_build(AF_INET, &local_be, sizeof(local_be));
        nl_addr *p = nl_addr_build(AF_INET, &peer_be,  sizeof(peer_be));

        if (!l || !p)
        {
            if (l) nl_addr_put(l);
            if (p) nl_addr_put(p);
            rtnl_addr_put(a);
            return false;
        }

        rtnl_addr_set_local(a, l);
        rtnl_addr_set_peer(a,  p);
        rtnl_addr_set_prefixlen(a, prefix);

        const int rc = rtnl_addr_add(sk, a, 0);

        nl_addr_put(l);
        nl_addr_put(p);
        rtnl_addr_put(a);
        return rc == 0 || rc == -NLE_EXIST;
    }

    inline bool addr_add_v6_local(nl_sock                              *sk,
                      int                                   ifindex,
                      const std::array<std::uint8_t, 16>  &local,
                      std::uint8_t                         prefix)
    {
        rtnl_addr *a = rtnl_addr_alloc();
        if (!a) return false;
        rtnl_addr_set_ifindex(a, ifindex);

        nl_addr *l = nl_addr_build(AF_INET6, local.data(), 16);
        if (!l)
        {
            rtnl_addr_put(a);
            return false;
        }

        rtnl_addr_set_local(a, l);
        rtnl_addr_set_prefixlen(a, prefix);
        rtnl_addr_set_flags(a, IFA_F_NODAD | IFA_F_NOPREFIXROUTE);

        const int rc = rtnl_addr_add(sk, a, 0);

        nl_addr_put(l);
        rtnl_addr_put(a);
        return rc == 0 || rc == -NLE_EXIST;
    }

    inline bool route_add_onlink_host_v6(nl_sock                             *sk,
                             int                                  ifindex,
                             const std::array<std::uint8_t, 16> &dst128)
    {
        rtnl_route *r = rtnl_route_alloc();
        if (!r) return false;

        rtnl_route_set_family(r, AF_INET6);
        rtnl_route_set_scope(r, RT_SCOPE_LINK);

        nl_addr *d = nl_addr_build(AF_INET6, dst128.data(), 16);
        if (!d)
        {
            rtnl_route_put(r);
            return false;
        }
        nl_addr_set_prefixlen(d, 128);
        rtnl_route_set_dst(r, d);

        rtnl_nexthop *nh = rtnl_route_nh_alloc();
        if (!nh)
        {
            nl_addr_put(d);
            rtnl_route_put(r);
            return false;
        }
        rtnl_route_nh_set_ifindex(nh, ifindex);
        rtnl_route_add_nexthop(r, nh);

        const int rc = rtnl_route_add(sk, r, 0);

        nl_addr_put(d);
        rtnl_route_put(r);
        return rc == 0 || rc == -NLE_EXIST;
    }

    inline std::optional<std::string> find_default_oifname(nl_sock *sk,
                         int      family)
    {
        nl_cache *rcache = nullptr;
        nl_cache *lcache = nullptr;

        if (rtnl_route_alloc_cache(sk, family, 0, &rcache) < 0)
            return std::nullopt;
        if (rtnl_link_alloc_cache(sk, AF_UNSPEC, &lcache) < 0)
        {
            nl_cache_free(rcache);
            return std::nullopt;
        }

        int oif = 0;
        for (nl_object *it = nl_cache_get_first(rcache);
             it;
             it = nl_cache_get_next(it))
        {
            auto *r = reinterpret_cast<rtnl_route *>(it);
            nl_addr *dst = rtnl_route_get_dst(r);
            const bool is_default =
                    (dst == nullptr) || (nl_addr_get_prefixlen(dst) == 0);
            if (!is_default) continue;
            if (rtnl_route_get_table(r) != RT_TABLE_MAIN) continue;

            const int nn = rtnl_route_get_nnexthops(r);
            if (nn > 0)
            {
                rtnl_nexthop *nh = rtnl_route_nexthop_n(r, 0);
                if (nh)
                {
                    oif = rtnl_route_nh_get_ifindex(nh);
                    if (oif > 0) break;
                }
            }
        }

        std::string name;
        if (oif > 0)
        {
            rtnl_link *link = rtnl_link_get(lcache, oif);
            if (link)
            {
                name = rtnl_link_get_name(link);
                rtnl_link_put(link);
            }
        }

        nl_cache_free(rcache);
        nl_cache_free(lcache);
        if (name.empty()) return std::nullopt;
        return name;
    }

    inline bool nft_apply(const std::string &commands)
    {
        nft_ctx *ctx = nft_ctx_new(NFT_CTX_DEFAULT);
        if (!ctx) return false;

        nft_ctx_buffer_output(ctx);
        nft_ctx_buffer_error(ctx);

        const int rc = nft_run_cmd_from_buffer(ctx, commands.c_str());
        if (rc != 0)
        {
            const char *err = nft_ctx_get_error_buffer(ctx);
            bool benign     = false;
            if (err)
            {
                std::string e = err;
                for (auto &c : e) c = std::tolower(c);
                if (e.find("exist")   != std::string::npos ||
                    e.find("already") != std::string::npos)
                    benign = true;
            }
            nft_ctx_free(ctx);
            return benign;
        }
        nft_ctx_free(ctx);
        return true;
    }

    inline bool ensure_nat44(const std::string &oifname,
                 const std::string &src_cidr)
    {
        std::string cmd;
        cmd  = "add table ip nat\n";
        cmd += "add chain ip nat POSTROUTING { type nat hook postrouting priority 100 ; }\n";
        cmd += "add rule ip nat POSTROUTING oifname \"" +
               oifname + "\" ip saddr " + src_cidr +
               " counter masquerade\n";
        return nft_apply(cmd);
    }

    inline bool ensure_nat66(const std::string &oifname,
                 const std::string &src_cidr)
    {
        std::string cmd;
        cmd  = "add table ip6 nat\n";
        cmd += "add chain ip6 nat POSTROUTING { type nat hook postrouting priority 100 ; }\n";
        cmd += "add rule ip6 nat POSTROUTING oifname \"" +
               oifname + "\" ip6 saddr " + src_cidr +
               " counter masquerade\n";
        return nft_apply(cmd);
    }

    inline bool ApplyServerSide(const std::string &ifname,
                    const Params      &p = Params{})
    {
        const int ifindex = static_cast<int>(if_nametoindex(ifname.c_str()));
        if (ifindex == 0)
        {
            std::cerr << "if_nametoindex failed for " << ifname << "\n";
            return false;
        }

        nl_sock *sk = nl_connect_route();
        if (!sk)
        {
            std::cerr << "nl_connect NETLINK_ROUTE failed\n";
            return false;
        }

        bool ok = true;
        ok &= link_set_up_and_mtu(sk, ifindex, p.mtu);

        write_if_sysctl(ifname, "accept_ra",    "0");
        write_if_sysctl(ifname, "autoconf",     "0");
        write_if_sysctl(ifname, "disable_ipv6", "0");

        ok &= addr_flush_all(sk, ifindex);
        ok &= addr_add_v4_p2p(sk, ifindex,
                              p.v4_local.addr_be, p.v4_peer_be,
                              p.v4_local.prefix);

        ok &= addr_add_v6_local(sk, ifindex,
                                p.v6_local.addr, p.v6_local.prefix);
        (void) route_add_onlink_host_v6(sk, ifindex, p.v6_peer);

        nl_socket_free(sk);

        ok &= write_sysctl("/proc/sys/net/ipv4/ip_forward", "1");
        ok &= write_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1");

        nl_sock *sk2 = nl_connect_route();
        if (!sk2) return false;

        auto wan4 = find_default_oifname(sk2, AF_INET);
        auto wan6 = find_default_oifname(sk2, AF_INET6);
        nl_socket_free(sk2);

        if (wan4) { (void) ensure_nat44(*wan4, p.nat44_src); }
        if (wan6) { (void) ensure_nat66(*wan6, p.nat66_src); }

        return ok;
    }
} // namespace NetConfig
