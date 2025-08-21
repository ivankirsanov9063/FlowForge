#include "Network.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <iostream>
#include <cstring>
#include <cerrno>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <algorithm>

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
    bool write_sysctl(const char *path,
                      const char *val)
    {
        int fd = ::open(path, O_WRONLY | O_CLOEXEC);
        if (fd < 0) return false;

        const ssize_t need = static_cast<ssize_t>(std::strlen(val));
        const ssize_t n    = ::write(fd, val, need);
        ::close(fd);

        return n == need;
    }

    bool write_if_sysctl(const std::string &ifname,
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

    // --- IPv4 per-interface sysctl: /proc/sys/net/ipv4/conf/<if>/<key>
    static bool write_if_sysctl_v4(const std::string &ifname,
                                   const char        *key,
                                   const char        *val)
    {
        char path[256];
        std::snprintf(path, sizeof(path),
                      "/proc/sys/net/ipv4/conf/%s/%s",
                      ifname.c_str(), key);

        int fd = ::open(path, O_WRONLY | O_CLOEXEC);
        if (fd < 0) return false;
        const ssize_t need = static_cast<ssize_t>(std::strlen(val));
        const ssize_t n    = ::write(fd, val, need);
        ::close(fd);
        return n == need;
    }

    nl_sock *nl_connect_route()
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

    bool link_set_up_and_mtu(nl_sock *sk,
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

    bool addr_add_v4_local(nl_sock    *sk,
                           int         ifindex,
                           std::uint32_t local_be,
                           std::uint8_t  prefix)
    {
        rtnl_addr *a = rtnl_addr_alloc();
        if (!a) return false;
        rtnl_addr_set_ifindex(a, ifindex);
        rtnl_addr_set_family(a, AF_INET);

        nl_addr *l = nl_addr_build(AF_INET, &local_be, sizeof(local_be));
        if (!l)
        {
            rtnl_addr_put(a);
            return false;
        }

        rtnl_addr_set_local(a, l);
        rtnl_addr_set_prefixlen(a, prefix);
        // Для TUN p2p не нужен: подключённый маршрут на весь префикс появится автоматически.

        const int rc = rtnl_addr_add(sk, a, 0);

        nl_addr_put(l);
        rtnl_addr_put(a);
        return rc == 0 || rc == -NLE_EXIST;
    }

    bool addr_flush_all(nl_sock *sk,
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

    bool addr_add_v4_p2p(nl_sock    *sk,
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

    bool addr_add_v6_local(nl_sock                              *sk,
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

    bool route_add_onlink_host_v6(nl_sock                             *sk,
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

    std::optional<std::string> find_default_oifname(nl_sock *sk,
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

    bool nft_feature_probe()
    {
        nft_ctx *ctx = nft_ctx_new(NFT_CTX_DEFAULT);
        if (!ctx) return false;
        nft_ctx_buffer_output(ctx);
        nft_ctx_buffer_error(ctx);

        // Попытка №1: "list tables" (не меняет состояние)
        int rc = nft_run_cmd_from_buffer(ctx, "list tables");
        if (rc != 0)
        {
            // Запасной путь: пробуем создать/удалить временную таблицу
            (void) nft_run_cmd_from_buffer(ctx, "add table inet flowforge_probe");
            rc = nft_run_cmd_from_buffer(ctx, "delete table inet flowforge_probe");
        }

        nft_ctx_free(ctx);
        return rc == 0;
    }


    bool nft_apply(const std::string &commands)
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
                std::transform(e.begin(), e.end(), e.begin(),
                               [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
                // 1) idempotency: "exists"/"already"
                if (e.find("exist") != std::string::npos || e.find("already") != std::string::npos)
                        benign = true;
                // 2) best-effort для удалений/flush: "no such file or directory"
                if (!benign && e.find("no such file or directory") != std::string::npos)
                {
                    std::string cmd_lower = commands;
                    std::transform(cmd_lower.begin(), cmd_lower.end(), cmd_lower.begin(),
                                   [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
                    if (cmd_lower.find("delete ") != std::string::npos ||
                        cmd_lower.find("flush chain") != std::string::npos)
                        benign = true;
                }
            }
            if (!benign) {
                std::cerr << "[nft] ERROR: " << (err ? err : "(no error text)") << "\n";
                std::cerr << "[nft] COMMANDS:\n" << commands << "\n";
            }
            nft_ctx_free(ctx);
            return benign;
        }
        nft_ctx_free(ctx);
        return true;
    }

    bool ensure_nat44(const std::string &oifname,
                      const std::string &src_cidr)
    {
        std::string cmd;
        cmd  = "add table ip flowforge_nat\n";
        cmd += "add chain ip flowforge_nat postrouting { type nat hook postrouting priority 100 ; policy accept; }\n";
        cmd += "flush chain ip flowforge_nat postrouting\n";
        cmd += "add rule ip flowforge_nat postrouting "
               "ip saddr " + src_cidr + " "
               "oifname \"" + oifname + "\" "
               "counter masquerade "
               "comment \"flowforge:auto\"\n";
        return nft_apply(cmd);
    }

    bool ensure_nat66(const std::string &oifname,
                      const std::string &src_cidr)
    {
        std::string cmd;
        cmd  = "add table ip6 flowforge_nat\n";
        cmd += "add chain ip6 flowforge_nat postrouting { type nat hook postrouting priority 100 ; policy accept; }\n";
        cmd += "flush chain ip6 flowforge_nat postrouting\n";
        cmd += "add rule ip6 flowforge_nat postrouting "
               "ip6 saddr " + src_cidr + " "
               "oifname \"" + oifname + "\" "
               "counter masquerade "
               "comment \"flowforge:auto\"\n";

        return nft_apply(cmd);
    }

    // --- MSS clamp в postrouting (идемпотентно): inet/flowforge_post
    static bool ensure_mss_clamp(const std::optional<std::string> &wan4,
                                 const std::optional<std::string> &wan6,
                                 const Params                      &p)
    {
        auto run = [](const std::string &cmd)->bool {
            if (!nft_apply(cmd)) { std::cerr << "[mss] failed cmd: " << cmd; return false; }
            return true;
        };

        // 1) таблица и цепочка — РАЗДЕЛЬНО (чтобы "exist" не обрывал весь буфер)
        if (!run("add table inet flowforge_post\n")) {
            (void) nft_apply("delete table inet flowforge_post\n");
            if (!run("add table inet flowforge_post\n")) return false;
        }
        if (!run("add chain inet flowforge_post postrouting { type filter hook postrouting priority -150; policy accept; }\n")) {
            (void) nft_apply("delete table inet flowforge_post\n");
            if (!run("add table inet flowforge_post\n")) return false;
            if (!run("add chain inet flowforge_post postrouting { type filter hook postrouting priority -150; policy accept; }\n")) return false;
        }

        // 2) очищаем рабочую цепочку
        if (!run("flush chain inet flowforge_post postrouting\n")) {
            (void) nft_apply("delete table inet flowforge_post\n");
            if (!run("add table inet flowforge_post\n")) return false;
            if (!run("add chain inet flowforge_post postrouting { type filter hook postrouting priority -150; policy accept; }\n")) return false;
        }

        // 3) правила
        std::string rules;
        if (wan4 && !p.nat44_src.empty())
        {
            rules += "add rule inet flowforge_post postrouting "
                     "ip saddr " + p.nat44_src + " "
                     "oifname \"" + *wan4 + "\" "
                     "tcp flags syn tcp option maxseg size set rt mtu "
                     "comment \"flowforge:mss\"\n";
        }
        if (wan6 && !p.nat66_src.empty())
        {
            rules += "add rule inet flowforge_post postrouting "
                     "ip6 saddr " + p.nat66_src + " "
                     "oifname \"" + *wan6 + "\" "
                     "tcp flags syn tcp option maxseg size set rt mtu "
                     "comment \"flowforge:mss6\"\n";
        }
        return rules.empty() ? true : nft_apply(rules);
    }

    // ---- Политики файрвола для TUN ----------------------------------------------------------
    bool ensure_fw_tun(const std::string &ifname, const Params &p)
    {
        auto run = [](const std::string &cmd)->bool {
            if (!nft_apply(cmd)) { std::cerr << "[fw] failed cmd: " << cmd; return false; }
            return true;
        };

        // 1) Таблица — отдельно
        if (!run("add table inet flowforge_fw\n")) {
            (void) nft_apply("delete table inet flowforge_fw\n");
            if (!run("add table inet flowforge_fw\n")) return false;
        }
        // 2) Hook-цепочки — отдельно (фикс синтаксиса: 'forward { ... }' с пробелом)
        if (!run("add chain inet flowforge_fw input { type filter hook input priority 0; policy accept; }\n")) {
            (void) nft_apply("delete table inet flowforge_fw\n");
            if (!run("add table inet flowforge_fw\n")) return false;
            if (!run("add chain inet flowforge_fw input { type filter hook input priority 0; policy accept; }\n")) return false;
        }
        if (!run("add chain inet flowforge_fw forward { type filter hook forward priority 0; policy accept; }\n")) {
            (void) nft_apply("delete table inet flowforge_fw\n");
            if (!run("add table inet flowforge_fw\n")) return false;
            if (!run("add chain inet flowforge_fw input { type filter hook input priority 0; policy accept; }\n")) return false;
            if (!run("add chain inet flowforge_fw forward { type filter hook forward priority 0; policy accept; }\n")) return false;
        }
        // 3) Рабочие (не hook) цепочки без policy (policy допустим только в hook-цепях)
        (void) nft_apply("add chain inet flowforge_fw tun_in\n");
        (void) nft_apply("add chain inet flowforge_fw tun_fwd\n");
        // 4) Привязка к нашему интерфейсу (идемпотентно)
        (void) nft_apply("add rule inet flowforge_fw input  iifname \"" + ifname + "\" jump tun_in\n");
        (void) nft_apply("add rule inet flowforge_fw forward iifname \"" + ifname + "\" jump tun_fwd\n");

        // 5) Чистим рабочие цепочки (с перезапуском «с нуля» при сбое flush)
        if (!run("flush chain inet flowforge_fw tun_in\n")) {
            (void) nft_apply("delete table inet flowforge_fw\n");
            if (!run("add table inet flowforge_fw\n")) return false;
            if (!run("add chain inet flowforge_fw input { type filter hook input priority 0; policy accept; }\n")) return false;
            if (!run("add chain inet flowforge_fw forward { type filter hook forward priority 0; policy accept; }\n")) return false;
            if (!run("add chain inet flowforge_fw tun_in\n")) return false;
            if (!run("add chain inet flowforge_fw tun_fwd\n")) return false;
            (void) nft_apply("add rule inet flowforge_fw input  iifname \"" + ifname + "\" jump tun_in\n");
            (void) nft_apply("add rule inet flowforge_fw forward iifname \"" + ifname + "\" jump tun_fwd\n");
        }
        if (!run("flush chain inet flowforge_fw tun_fwd\n")) {
            (void) nft_apply("delete table inet flowforge_fw\n");
            if (!run("add table inet flowforge_fw\n")) return false;
            if (!run("add chain inet flowforge_fw input { type filter hook input priority 0; policy accept; }\n")) return false;
            if (!run("add chain inet flowforge_fw forward { type filter hook forward priority 0; policy accept; }\n")) return false;
            if (!run("add chain inet flowforge_fw tun_in\n")) return false;
            if (!run("add chain inet flowforge_fw tun_fwd\n")) return false;
            (void) nft_apply("add rule inet flowforge_fw input  iifname \"" + ifname + "\" jump tun_in\n");
            (void) nft_apply("add rule inet flowforge_fw forward iifname \"" + ifname + "\" jump tun_fwd\n");
        }

        const std::string net4 = to_network_cidr(p.v4_local);
        const std::string net6 = to_network_cidr(p.v6_local);

        // 6) Правила tun_in (INPUT на TUN): default drop, разрешаем только нужное
        if (!run("add rule inet flowforge_fw tun_in ct state invalid drop\n")) return false;
        if (!run("add rule inet flowforge_fw tun_in ct state established,related accept\n")) return false;
        if (p.v4_local.prefix > 0)
        {
            std::string r = "add rule inet flowforge_fw tun_in ip saddr != " + net4 + " drop\n";
            if (!run(r)) return false;
        }
        if (p.v6_local.prefix > 0)
        {
            std::string r = "add rule inet flowforge_fw tun_in ip6 saddr != " + net6 + " drop\n";
            if (!run(r)) return false;
        }
        // ICMP/ICMPv6 — best-effort (мета-протоколы для inet-семейства)
        (void) nft_apply(
            "add rule inet flowforge_fw tun_in meta l4proto icmp "
            "icmp type { echo-request, destination-unreachable, time-exceeded, parameter-problem } "
            "limit rate 10/second accept\n");
        (void) nft_apply(
            "add rule inet flowforge_fw tun_in meta l4proto icmpv6 "
            "icmpv6 type { echo-request, packet-too-big, time-exceeded, parameter-problem, destination-unreachable } "
            "limit rate 10/second accept\n");
        // default-drop для входящего трафика с TUN
        if (!run("add rule inet flowforge_fw tun_in counter drop\n")) return false;

        // 7) Правила tun_fwd (FORWARD из TUN): антиспуфинг + состояние
        if (!run("add rule inet flowforge_fw tun_fwd ct state invalid drop\n")) return false;
        if (p.v4_local.prefix > 0)
        {
            std::string r = "add rule inet flowforge_fw tun_fwd ip saddr != " + net4 + " drop\n";
            if (!run(r)) return false;
        }
        if (p.v6_local.prefix > 0)
        {
            std::string r = "add rule inet flowforge_fw tun_fwd ip6 saddr != " + net6 + " drop\n";
            if (!run(r)) return false;
        }
        if (!run("add rule inet flowforge_fw tun_fwd ct state established,related accept\n")) return false;
        if (!run("add rule inet flowforge_fw tun_fwd accept\n")) return false;

        return true;
    }

    // ---- CIDR parsing & normalization ---------------------------------------------------------
    bool parse_cidr4(const std::string &s, CidrV4 &out)
    {
        auto pos = s.find('/');
        std::string ip = (pos == std::string::npos) ? s : s.substr(0, pos);
        int pref = (pos == std::string::npos) ? 32 : std::stoi(s.substr(pos + 1));
        if (pref < 0 || pref > 32) return false;

        in_addr ia{};
        if (inet_pton(AF_INET, ip.c_str(), &ia) != 1) return false;
        // inet_pton кладёт в network byte order — это и есть big-endian
        std::memcpy(&out.addr_be, &ia.s_addr, sizeof(out.addr_be));
        out.prefix = static_cast<std::uint8_t>(pref);
        return true;
    }

    bool parse_cidr6(const std::string &s, CidrV6 &out)
    {
        auto pos = s.find('/');
        std::string ip = (pos == std::string::npos) ? s : s.substr(0, pos);
        int pref = (pos == std::string::npos) ? 128 : std::stoi(s.substr(pos + 1));
        if (pref < 0 || pref > 128) return false;

        in6_addr ia6{};
        if (inet_pton(AF_INET6, ip.c_str(), &ia6) != 1) return false;
        std::memcpy(out.addr.data(), &ia6, 16);
        out.prefix = static_cast<std::uint8_t>(pref);
        return true;
    }

    static void mask_ipv6(std::array<std::uint8_t,16> &a, int prefix)
    {
        if (prefix <= 0) { a.fill(0); return; }
        if (prefix >= 128) return;
        int full = prefix / 8;
        int part = prefix % 8;
        for (int i = full + 1; i < 16; ++i) a[i] = 0;
        if (part != 0)
        {
            std::uint8_t mask = static_cast<std::uint8_t>(0xFFu << (8 - part));
            a[full] &= mask;
            for (int i = full + 1; i < 16; ++i) a[i] = 0;
        }
    }

    std::string to_network_cidr(const CidrV4 &c)
    {
        std::uint32_t be = c.addr_be;
        std::uint32_t host = (c.prefix == 0) ? 0xFFFFFFFFu : (0xFFFFFFFFu >> c.prefix);
        std::uint32_t net_be = be & ~htonl(host);
        in_addr ia{};
        std::memcpy(&ia.s_addr, &net_be, sizeof(net_be));
        char buf[INET_ADDRSTRLEN]{};
        inet_ntop(AF_INET, &ia, buf, sizeof(buf));
        std::ostringstream oss;
        oss << buf << "/" << static_cast<int>(c.prefix);
        return oss.str();
    }

    std::string to_network_cidr(const CidrV6 &c)
    {
        auto bytes = c.addr;
        mask_ipv6(bytes, c.prefix);
        in6_addr ia6{};
        std::memcpy(&ia6, bytes.data(), 16);
        char buf[INET6_ADDRSTRLEN]{};
        inet_ntop(AF_INET6, &ia6, buf, sizeof(buf));
        std::ostringstream oss;
        oss << buf << "/" << static_cast<int>(c.prefix);
        return oss.str();
    }

    void ApplyServerSide(const std::string &ifname,
                         const Params      &p,
                         bool with_nat_fw)

    {
        const int ifindex = static_cast<int>(if_nametoindex(ifname.c_str()));
        if (ifindex == 0)
        {
            throw std::runtime_error("if_nametoindex failed for " + ifname);
        }

        nl_sock *sk = nl_connect_route();
        if (!sk)
        {
            throw std::runtime_error("nl_connect NETLINK_ROUTE failed");
        }

        if (!link_set_up_and_mtu(sk, ifindex, p.mtu))
        {
            nl_socket_free(sk);
            throw std::runtime_error("link_set_up_and_mtu failed for " + ifname);
        }

        if (!write_if_sysctl(ifname, "accept_ra", "0"))
        {
            nl_socket_free(sk);
            throw std::runtime_error("sysctl net.ipv6.conf." + ifname + ".accept_ra=0 failed");
        }
        if (!write_if_sysctl(ifname, "autoconf", "0"))
        {
            nl_socket_free(sk);
            throw std::runtime_error("sysctl net.ipv6.conf." + ifname + ".autoconf=0 failed");
        }
        if (!write_if_sysctl(ifname, "disable_ipv6", "0"))
        {
            nl_socket_free(sk);
            throw std::runtime_error("sysctl net.ipv6.conf." + ifname + ".disable_ipv6=0 failed");
        }

        if (!addr_flush_all(sk, ifindex))
        {
            nl_socket_free(sk);
            throw std::runtime_error("addr_flush_all failed for " + ifname);
        }
        if (!addr_add_v4_local(sk, ifindex, p.v4_local.addr_be, p.v4_local.prefix))
        {
            nl_socket_free(sk);
            throw std::runtime_error("addr_add_v4_local failed for " + ifname);
        }

        if (!addr_add_v6_local(sk, ifindex, p.v6_local.addr, p.v6_local.prefix))
        {
            nl_socket_free(sk);
            throw std::runtime_error("addr_add_v6_local failed for " + ifname);
        }

        nl_socket_free(sk);

        if (with_nat_fw)
        {
            // Перед применением NAT/MSS убеждаемся, что nftables поддержан.
            if (!nft_feature_probe())
            {
                throw std::runtime_error(
                    "nftables недоступен (ядро/пользовательское окружение). "
                    "Установите nftables/переключите альтернативы или запустите с --no-nat");
            }

            // --- Baseline sysctl для маршрутизатора (best-effort) ---------------------------
            // IPv6: глобально запретить RA (на Router интерфейсах оно не нужно)
            if (!write_sysctl("/proc/sys/net/ipv6/conf/all/accept_ra", "0"))
                std::cerr << "WARN: sysctl net.ipv6.conf.all.accept_ra=0 failed\n";
            if (!write_sysctl("/proc/sys/net/ipv6/conf/default/accept_ra", "0"))
                std::cerr << "WARN: sysctl net.ipv6.conf.default.accept_ra=0 failed\n";

            // IPv4: запретить ICMP redirects (глобально и по умолчанию)
            if (!write_sysctl("/proc/sys/net/ipv4/conf/all/accept_redirects", "0"))
                std::cerr << "WARN: sysctl net.ipv4.conf.all.accept_redirects=0 failed\n";
            if (!write_sysctl("/proc/sys/net/ipv4/conf/default/accept_redirects", "0"))
                std::cerr << "WARN: sysctl net.ipv4.conf.default.accept_redirects=0 failed\n";
            if (!write_sysctl("/proc/sys/net/ipv4/conf/all/send_redirects", "0"))
                std::cerr << "WARN: sysctl net.ipv4.conf.all.send_redirects=0 failed\n";
            if (!write_sysctl("/proc/sys/net/ipv4/conf/default/send_redirects", "0"))
                std::cerr << "WARN: sysctl net.ipv4.conf.default.send_redirects=0 failed\n";

            // IPv6: запретить ICMPв6 redirects (глобально и по умолчанию)
            if (!write_sysctl("/proc/sys/net/ipv6/conf/all/accept_redirects", "0"))
                std::cerr << "WARN: sysctl net.ipv6.conf.all.accept_redirects=0 failed\n";
            if (!write_sysctl("/proc/sys/net/ipv6/conf/default/accept_redirects", "0"))
                std::cerr << "WARN: sysctl net.ipv6.conf.default.accept_redirects=0 failed\n";

            // Hairpin/маскарадинг может требовать accept_local=1 (делаем только в режиме NAT/FW)
            if (!write_sysctl("/proc/sys/net/ipv4/conf/all/accept_local", "1"))
                std::cerr << "WARN: sysctl net.ipv4.conf.all.accept_local=1 failed\n";
            if (!write_sysctl("/proc/sys/net/ipv4/conf/default/accept_local", "1"))
                std::cerr << "WARN: sysctl net.ipv4.conf.default.accept_local=1 failed\n";

            if (!write_sysctl("/proc/sys/net/ipv4/ip_forward", "1"))
            {
                throw std::runtime_error("sysctl net.ipv4.ip_forward=1 failed");
            }
            if (!write_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1"))
            {
                throw std::runtime_error("sysctl net.ipv6.conf.all.forwarding=1 failed");
            }
        }
        else
        {
            // Режим без NAT: если nft доступен — всё равно зададим базовый fw на TUN (best-effort)
            if (nft_feature_probe())
            {
                if (!ensure_fw_tun(ifname, p))
                {
                    std::cerr << "WARN: ensure_fw_tun failed (skipped)\n";
                }
            }
            else
            {
                std::cerr << "WARN: nftables unavailable — skipping TUN firewall\n";
            }
        }

        nl_sock *sk2 = nl_connect_route();
        if (!sk2)
        {
            throw std::runtime_error("nl_connect NETLINK_ROUTE failed (2)");
        }

        auto wan4 = find_default_oifname(sk2, AF_INET);
        auto wan6 = find_default_oifname(sk2, AF_INET6);
        nl_socket_free(sk2);

        if (with_nat_fw)
        {
            // rp_filter=0 на WAN (асимметрия/NAT), запрет redirect'ов (в т.ч. для default)
            if (wan4)
            {
                (void) write_if_sysctl_v4(*wan4, "rp_filter", "0");
                (void) write_sysctl("/proc/sys/net/ipv4/conf/all/accept_redirects",     "0");
                (void) write_sysctl("/proc/sys/net/ipv4/conf/default/accept_redirects", "0");
                (void) write_sysctl("/proc/sys/net/ipv4/conf/all/send_redirects",       "0");
                (void) write_sysctl("/proc/sys/net/ipv4/conf/default/send_redirects",   "0");
            }

            // NAT (идемпотентно в своих таблицах)
            if (wan4 && !ensure_nat44(*wan4, p.nat44_src))
            {
                throw std::runtime_error("ensure_nat44 failed (oif=" + *wan4 + ", src=" + p.nat44_src + ")");
            }
            if (wan6 && !ensure_nat66(*wan6, p.nat66_src))
            {
                throw std::runtime_error("ensure_nat66 failed (oif=" + *wan6 + ", src=" + p.nat66_src + ")");
            }

            // TCP MSS clamp to PMTU (идемпотентно). На старых nft возможна неподдержка — не фатально.
            if (!ensure_mss_clamp(wan4, wan6, p))
            {
                std::cerr << "WARN: ensure_mss_clamp failed (MSS clamp skipped)\n";
            }

            // Политики файрвола на TUN обязательны при наличии nft
            if (!ensure_fw_tun(ifname, p))
            {
                throw std::runtime_error("ensure_fw_tun failed");
            }
        }
    }
} // namespace NetConfig
