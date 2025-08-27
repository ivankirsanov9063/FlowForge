#include "FirewallRules.hpp"
#include "Logger.hpp"
#include <stdexcept>
#include <cstring>
#include <nftables/libnftables.h>
#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/route/route.h>
#include <netlink/route/link.h>
#include <net/if.h>
#include <fstream>
#include <arpa/inet.h>

namespace {
    struct NlSock {
        nl_sock *sk {nullptr};
        NlSock() {
            sk = nl_socket_alloc();
            if (!sk) throw std::runtime_error("nl_socket_alloc failed");
            int rc = nl_connect(sk, NETLINK_ROUTE);
            if (rc < 0) { std::string msg = std::string("nl_connect: ")+nl_geterror(rc);
                nl_socket_free(sk); sk=nullptr; throw std::runtime_error(msg); }
        }
        ~NlSock(){ if (sk) nl_socket_free(sk); }
        NlSock(const NlSock&)=delete; NlSock& operator=(const NlSock&)=delete;
    };
    static std::string IfindexToName(nl_sock *sk, int ifindex) {
        nl_cache *lcache=nullptr; if (rtnl_link_alloc_cache(sk, AF_UNSPEC, &lcache)<0) return {};
        rtnl_link *lnk = rtnl_link_get(lcache, ifindex);
        std::string name; if (lnk){ if (const char *n=rtnl_link_get_name(lnk)) name=n; rtnl_link_put(lnk); }
        nl_cache_free(lcache); return name;
    }
}

bool FirewallRules::IsIPv6Literal_(const std::string &s) { return s.find(':') != std::string::npos; }
std::string FirewallRules::NormalizeIp_(std::string ip) { if (!ip.empty() && ip.front()=='[' && ip.back()==']') return ip.substr(1, ip.size()-2); return ip; }

std::string FirewallRules::DetectWanIfname_()
{
    try {
        NlSock nl;
        for (int fam : { AF_INET, AF_INET6 }) {
            nl_cache *rcache=nullptr; if (rtnl_route_alloc_cache(nl.sk, fam, 0, &rcache)<0) continue;
            for (rtnl_route *r=(rtnl_route*)nl_cache_get_first(rcache); r; r=(rtnl_route*)nl_cache_get_next((nl_object*)r)) {
                nl_addr *dst = rtnl_route_get_dst(r); if (!dst) continue;
                if (nl_addr_get_family(dst)!=fam || nl_addr_get_prefixlen(dst)!=0) continue;
                rtnl_nexthop *nh = rtnl_route_nexthop_n(r,0); if (!nh) continue;
                int ifindex = rtnl_route_nh_get_ifindex(nh); if (ifindex<=0) continue;
                std::string ifname = IfindexToName(nl.sk, ifindex); nl_cache_free(rcache); return ifname;
            }
            nl_cache_free(rcache);
        }
    } catch (const std::exception &e) { LOGW("firewall") << "WAN detect failed: " << e.what(); }
    return {};
}

FirewallRules::FirewallRules(const Params &params) : p_(params)
{
    if (p_.tun_ifname.empty()) throw std::invalid_argument("FirewallRules: tun_ifname is empty");
    if (p_.server_ip.empty() || p_.server_port==0) throw std::invalid_argument("FirewallRules: server_ip/port are required");
    CreateCtx_();
}
FirewallRules::~FirewallRules(){ try{ Revert(); }catch(...){} DestroyCtx_(); }
FirewallRules::FirewallRules(FirewallRules&& o) noexcept { ctx_=o.ctx_; p_=std::move(o.p_); applied_=o.applied_; o.ctx_=nullptr; o.applied_=false; }
FirewallRules& FirewallRules::operator=(FirewallRules&& o) noexcept { if (this==&o) return *this; try{Revert();}catch(...){} DestroyCtx_(); ctx_=o.ctx_; p_=std::move(o.p_); applied_=o.applied_; o.ctx_=nullptr; o.applied_=false; return *this; }
void FirewallRules::CreateCtx_(){ ctx_=nft_ctx_new(NFT_CTX_DEFAULT); if(!ctx_) throw std::runtime_error("libnftables: nft_ctx_new failed"); }
void FirewallRules::DestroyCtx_(){ if(ctx_){ nft_ctx_free(ctx_); ctx_=nullptr; } }
bool FirewallRules::RunCmd_(const std::string &cmd, bool ignore_error){ int rc=nft_run_cmd_from_buffer(ctx_, cmd.c_str()); if(rc<0){ if(ignore_error){ LOGD("firewall")<<"nft cmd ignored error: "<<cmd; return false; } LOGE("firewall")<<"nft cmd failed: "<<cmd; throw std::runtime_error("libnftables: command failed"); } LOGT("firewall")<<"nft ok: "<<cmd; return true; }

static std::vector<std::string> ParseNameservers(const std::string& path)
{
    std::ifstream f(path);
    std::vector<std::string> out;
    std::string tok;
    while (f >> tok)
    {
        if (tok == "nameserver")
        {
            std::string ip;
            if (f >> ip) out.push_back(ip);
        }
    }
    // dedup...
    return out;
}

bool IsIPv4(const std::string &s)
{
    if (s.empty())
    {
        return false;
    }

    // Быстрая проверка: только цифры и точки, ровно 3 точки, без ведущей/замыкающей точки
    int dot_count = 0;
    for (unsigned char ch : s)
    {
        if (ch == '.')
        {
            ++dot_count;
        }
        else if (!std::isdigit(ch))
        {
            return false;
        }
    }
    if (dot_count != 3 || s.front() == '.' || s.back() == '.')
    {
        return false;
    }

    struct in_addr addr{};
    return inet_pton(AF_INET, s.c_str(), &addr) == 1;
}


void FirewallRules::Apply()
{
    const std::string ip  = NormalizeIp_(p_.server_ip);
    const bool is_v6      = IsIPv6Literal_(ip);
    const std::string wan = DetectWanIfname_();

    LOGI("firewall") << "Apply: table="<<p_.table_name<<" chain="<<p_.chain_name
                     << " tun="<<p_.tun_ifname<<" wan="<<(wan.empty()?"-":wan)
                     << " server="<<ip<<":"<<p_.server_port
                     << " ks="<<(p_.enable_killswitch?"1":"0")
                     << " dns="<<(p_.allow_dns_bootstrap?"1":"0")
                     << " dhcp="<<(p_.allow_dhcp?"1":"0")
                     << " icmp="<<(p_.allow_icmp?"1":"0");

    RunCmd_("delete table inet " + p_.table_name, /*ignore_error=*/true);
    RunCmd_("add table inet " + p_.table_name);

    // policy accept — ничего не ломаем по умолчанию
    // OUTPUT: локально сгенерённые пакеты (в т.ч. UDP к серверу)
    RunCmd_("add chain inet " + p_.table_name + " " + p_.chain_name +
        " { type filter hook output priority " + std::to_string(p_.hook_priority) + "; policy accept; }");
    // FORWARD: трафик из/в TUN (иначе туннель не работает на системах с policy drop)
    RunCmd_("add chain inet " + p_.table_name +
        " fw { type filter hook forward priority " + std::to_string(p_.hook_priority) + "; policy accept; }");

    // base allow
    RunCmd_("add rule inet " + p_.table_name + " " + p_.chain_name + " ct state established,related accept");
    RunCmd_("add rule inet " + p_.table_name + " " + p_.chain_name + " oifname \"lo\" accept");
    RunCmd_("add rule inet " + p_.table_name + " " + p_.chain_name + " oifname \"" + p_.tun_ifname + "\" accept");
    if (p_.allow_icmp) {
        RunCmd_("add rule inet " + p_.table_name + " " + p_.chain_name + " ip protocol icmp accept");
        RunCmd_("add rule inet " + p_.table_name + " " + p_.chain_name + " meta l4proto icmpv6 accept");
    }
    // base allow (FORWARD): TUN <-> WAN
    RunCmd_("add rule inet " + p_.table_name + " fw ct state established,related accept");
    RunCmd_("add rule inet " + p_.table_name + " fw iifname \"" + p_.tun_ifname + "\" accept"); // внутрь -> наружу
    RunCmd_("add rule inet " + p_.table_name + " fw oifname \"" + p_.tun_ifname + "\" accept"); // наружу -> внутрь

    // сервер
    if (!is_v6) {
        if (p_.allow_udp) RunCmd_("add rule inet " + p_.table_name + " " + p_.chain_name + " ip daddr " + ip + " udp dport " + std::to_string(p_.server_port) + " accept");
        if (p_.allow_tcp) RunCmd_("add rule inet " + p_.table_name + " " + p_.chain_name + " ip daddr " + ip + " tcp dport " + std::to_string(p_.server_port) + " accept");
    } else {
        if (p_.allow_udp) RunCmd_("add rule inet " + p_.table_name + " " + p_.chain_name + " ip6 daddr " + ip + " udp dport " + std::to_string(p_.server_port) + " accept");
        if (p_.allow_tcp) RunCmd_("add rule inet " + p_.table_name + " " + p_.chain_name + " ip6 daddr " + ip + " tcp dport " + std::to_string(p_.server_port) + " accept");
    }

    // bootstrap на WAN (если нашли)
    if (!wan.empty()) {
        if (p_.allow_dns_bootstrap) {
            RunCmd_("add rule inet " + p_.table_name + " " + p_.chain_name + " oifname \"" + wan + "\" udp dport 53 accept");
            RunCmd_("add rule inet " + p_.table_name + " " + p_.chain_name + " oifname \"" + wan + "\" tcp dport 53 accept");

            if (p_.in_container)
            {
                auto ns = ParseNameservers("/etc/resolv.conf");
                for (const auto& ip : ns)
                {
                    if (IsIPv4(ip)) {
                        RunCmd_("add rule inet " + p_.table_name + " " + p_.chain_name + " ip daddr " + ip + " udp dport 53 accept");
                        RunCmd_("add rule inet " + p_.table_name + " " + p_.chain_name + " ip daddr " + ip + " tcp dport 53 accept");
                    } else {
                        RunCmd_("add rule inet " + p_.table_name + " " + p_.chain_name + " ip6 daddr " + ip + " udp dport 53 accept");
                        RunCmd_("add rule inet " + p_.table_name + " " + p_.chain_name + " ip6 daddr " + ip + " tcp dport 53 accept");
                    }
                }
            }
        }
        if (p_.allow_dhcp) {
            RunCmd_("add rule inet " + p_.table_name + " " + p_.chain_name + " oifname \"" + wan + "\" udp sport 68 udp dport 67 accept");
        }

        // Kill-switch включаем только если явно попросили
        // Kill-switch: отключаем только "не-туннельный" выход в WAN
        if (p_.enable_killswitch) {
            // Разрешения выше: (OUTPUT) сервер VPN, (FORWARD) iif/oif = TUN
                    RunCmd_("add rule inet " + p_.table_name + " " + p_.chain_name + " oifname \"" + wan + "\" counter drop");
            RunCmd_("add rule inet " + p_.table_name + " fw iifname != \"" + p_.tun_ifname + "\" oifname \"" + wan + "\" counter drop");
        } else {
            LOGW("firewall") << "Killswitch disabled (no WAN drop rule)";
        }
    } else {
        LOGW("firewall") << "WAN interface not detected; no WAN-specific rules installed";
    }

    applied_ = true;
    LOGI("firewall") << "Firewall rules applied";
}

void FirewallRules::Revert()
{
    if (!ctx_) return;
    if (RunCmd_("delete table inet " + p_.table_name, /*ignore_error=*/true))
        LOGI("firewall") << "Firewall rules reverted";
    else
        LOGD("firewall") << "No table to delete (already reverted)";
    applied_ = false;
}
