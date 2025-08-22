// NetWatcher.cpp — наблюдение за изменениями default route и пересборка NAT/MSS

#include "NetWatcher.hpp"
#include "Network.hpp"

#include <chrono>
#include <thread>
#include <mutex>
#include <optional>
#include <string>
#include <stdexcept>
#include <algorithm>

#include <linux/rtnetlink.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/cache.h>
#include <netlink/route/route.h>
#include <netlink/route/nexthop.h>
#include <netlink/errno.h>

namespace
{
    // Коллбек libnl: любое валидное сообщение маршрутизации — триггер на пересборку.
    int on_nl_valid(struct nl_msg *,
                    void *arg)
    {
        auto *self = static_cast<NetWatcher *>(arg);
        (void) self; // тяжёлую работу не делаем в коллбеке
        return NL_OK;
    }
}

NetWatcher::NetWatcher(const NetConfig::Params &params)
    : params_(params)
{
    // Требуем доступность nftables: на старых ядрах/дистрибутивах может не работать.
    if (!NetConfig::nft_feature_probe())
    {
        throw std::runtime_error("NetWatcher: nftables is not available on this platform");
    }

    sk_ = nl_socket_alloc();
    if (!sk_)
    {
        throw std::runtime_error("NetWatcher: nl_socket_alloc failed");
    }
    if (nl_connect(sk_, NETLINK_ROUTE) != 0)
    {
        nl_socket_free(sk_);
        sk_ = nullptr;
        throw std::runtime_error("NetWatcher: nl_connect NETLINK_ROUTE failed");
    }

    // Подписываемся на события изменения маршрутов IPv4/IPv6
    if (nl_socket_add_membership(sk_, RTNLGRP_IPV4_ROUTE) != 0)
    {
        nl_socket_free(sk_);
        sk_ = nullptr;
        throw std::runtime_error("NetWatcher: nl_socket_add_membership RTNLGRP_IPV4_ROUTE failed");
    }
    if (nl_socket_add_membership(sk_, RTNLGRP_IPV6_ROUTE) != 0)
    {
        nl_socket_free(sk_);
        sk_ = nullptr;
        throw std::runtime_error("NetWatcher: nl_socket_add_membership RTNLGRP_IPV6_ROUTE failed");
    }

    // Неблокирующий режим + периодический опрос
    if (nl_socket_set_nonblocking(sk_) != 0)
    {
        nl_socket_free(sk_);
        sk_ = nullptr;
        throw std::runtime_error("NetWatcher: nl_socket_set_nonblocking failed");
    }

    // Коллбек на валидные сообщения (содержание неважно — после события пересчитаем WAN)
    if (nl_socket_modify_cb(sk_, NL_CB_VALID, NL_CB_CUSTOM, &on_nl_valid, this) != 0)
    {
        nl_socket_free(sk_);
        sk_ = nullptr;
        throw std::runtime_error("NetWatcher: nl_socket_modify_cb(NL_CB_VALID) failed");
    }

    // Запускаем рабочий поток
    th_ = std::thread([this]
    {
        ThreadMain_();
    });
}

NetWatcher::~NetWatcher()
{
    stop_.store(true, std::memory_order_relaxed);

    if (th_.joinable())
    {
        th_.join();
    }
    if (sk_)
    {
        nl_socket_free(sk_);
        sk_ = nullptr;
    }
}

std::optional<std::string> NetWatcher::Wan4() const
{
    std::lock_guard<std::mutex> lock(mu_);
    return last_wan4_;
}

std::optional<std::string> NetWatcher::Wan6() const
{
    std::lock_guard<std::mutex> lock(mu_);
    return last_wan6_;
}

void NetWatcher::ThreadMain_()
{
    // Первичное применение: на текущий дефолт
    try
    {
        RecomputeAndApply_();
    }
    catch (const std::exception &)
    {
        stop_.store(true, std::memory_order_relaxed);
        return;
    }

    using namespace std::chrono_literals;

    while (!stop_.load(std::memory_order_relaxed))
    {
        int rc = nl_recvmsgs_default(sk_);
        if (rc < 0 && rc != -NLE_AGAIN)
        {
            stop_.store(true, std::memory_order_relaxed);
            break;
        }

        try
        {
            RecomputeAndApply_();
        }
        catch (const std::exception &)
        {
            stop_.store(true, std::memory_order_relaxed);
            break;
        }

        std::this_thread::sleep_for(200ms);
    }
}

void NetWatcher::RecomputeAndApply_()
{
    // Вычисляем актуальные WAN-ы на основе текущего состояния маршрутов
    auto wan4 = NetConfig::find_default_oifname(sk_, AF_INET);
    auto wan6 = NetConfig::find_default_oifname(sk_, AF_INET6);

    bool changed = false;
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (wan4 != last_wan4_ || wan6 != last_wan6_)
        {
            changed    = true;
            last_wan4_ = wan4;
            last_wan6_ = wan6;
        }
    }

    if (!changed)
    {
        return;
    }

    ApplyNatAndMss_(wan4, wan6, params_);
}

void NetWatcher::ApplyNatAndMss_(const std::optional<std::string> &wan4,
                                 const std::optional<std::string> &wan6,
                                 const NetConfig::Params          &p)
{
    // 1) NAT: чистим цепи в наших таблицах и, если WAN существует — ставим правило
    {
        // ip(v4)
        std::string cmd4;
        cmd4  = "add table ip flowforge_nat\n";
        cmd4 += "add chain ip flowforge_nat postrouting { type nat hook postrouting priority 100 ; policy accept; }\n";
        cmd4 += "flush chain ip flowforge_nat postrouting\n";
        if (!NetConfig::nft_apply(cmd4))
        {
            throw std::runtime_error("NetWatcher: nft apply for IPv4 NAT bootstrap failed");
        }

        if (wan4 && !p.nat44_src.empty())
        {
            (void) NetConfig::ensure_nat44(*wan4, p.nat44_src);
        }
    }
    {
        // ip6
        std::string cmd6;
        cmd6  = "add table ip6 flowforge_nat\n";
        cmd6 += "add chain ip6 flowforge_nat postrouting { type nat hook postrouting priority 100 ; policy accept; }\n";
        cmd6 += "flush chain ip6 flowforge_nat postrouting\n";
        if (!NetConfig::nft_apply(cmd6))
        {
            throw std::runtime_error("NetWatcher: nft apply for IPv6 NAT bootstrap failed");
        }

        if (wan6 && !p.nat66_src.empty())
        {
            (void) NetConfig::ensure_nat66(*wan6, p.nat66_src);
        }
    }

    // 2) MSS clamp: чистим и добавляем заново (как в Network.cpp)
    {
        // Шаг 1: гарантируем table/chain с ЧИСЛОВЫМ приоритетом (совместимо со старыми nft)
        std::string mk;
        mk  = "add table inet flowforge_post\n";
        mk += "add chain inet flowforge_post postrouting "
              "{ type filter hook postrouting priority -150; policy accept; }\n";

        if (!NetConfig::nft_apply(mk))
        {
            (void) NetConfig::nft_apply("delete table inet flowforge_post\n");
            if (!NetConfig::nft_apply(mk))
            {
                throw std::runtime_error("NetWatcher: nft apply for MSS table/chain failed");
            }
        }

        // Шаг 2: отдельный flush (старые nft падают, если делать всё одним батчем)
        if (!NetConfig::nft_apply("flush chain inet flowforge_post postrouting\n"))
        {
            (void) NetConfig::nft_apply("delete table inet flowforge_post\n");
            if (!NetConfig::nft_apply(mk))
            {
                throw std::runtime_error("NetWatcher: nft flush/recreate for MSS chain failed");
            }
        }

        // Шаг 3: правила (сначала современный синтаксис RT MTU, затем фоллбэк)
        std::string rules_rt;

        if (wan4 && !p.nat44_src.empty())
        {
            rules_rt += "add rule inet flowforge_post postrouting "
                        "ip saddr " + p.nat44_src + " "
                        "oifname \"" + *wan4 + "\" "
                        "tcp flags syn tcp option maxseg size set rt mtu "
                        "comment \"flowforge:mss\"\n";
        }
        if (wan6 && !p.nat66_src.empty())
        {
            rules_rt += "add rule inet flowforge_post postrouting "
                        "ip6 saddr " + p.nat66_src + " "
                        "oifname \"" + *wan6 + "\" "
                        "tcp flags syn tcp option maxseg size set rt mtu "
                        "comment \"flowforge:mss6\"\n";
        }

        if (!rules_rt.empty())
        {
            if (!NetConfig::nft_apply(rules_rt))
            {
                const int mss4 = std::max(536, p.mtu - 40);
                const int mss6 = std::max(536, p.mtu - 60);

                std::string rules_fix;

                if (wan4 && !p.nat44_src.empty())
                {
                    rules_fix += "add rule inet flowforge_post postrouting "
                                 "ip saddr " + p.nat44_src + " "
                                 "oifname \"" + *wan4 + "\" "
                                 "tcp flags syn tcp option maxseg size set " + std::to_string(mss4) + " "
                                 "comment \"flowforge:mss\"\n";
                }
                if (wan6 && !p.nat66_src.empty())
                {
                    rules_fix += "add rule inet flowforge_post postrouting "
                                 "ip6 saddr " + p.nat66_src + " "
                                 "oifname \"" + *wan6 + "\" "
                                 "tcp flags syn tcp option maxseg size set " + std::to_string(mss6) + " "
                                 "comment \"flowforge:mss6\"\n";
                }

                if (!rules_fix.empty() && !NetConfig::nft_apply(rules_fix))
                {
                    throw std::runtime_error("NetWatcher: nft apply for MSS fallback rules failed");
                }
            }
        }
    }
}
