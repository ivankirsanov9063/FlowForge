#include "NetWatcher.hpp"

#include "Network.hpp"

#include <linux/rtnetlink.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/cache.h>
#include <netlink/route/route.h>
#include <netlink/route/nexthop.h>

#include <chrono>
#include <stdexcept>

namespace
{
    // Коллбек libnl: любое валидное сообщение маршрутизации — триггер на пересборку.
    int on_nl_valid(struct nl_msg *, void *arg)
    {
        auto *self = static_cast<NetWatcher *>(arg);
        // Никакой тяжёлой работы в коллбеке — только флажок: делаем лениво в ThreadMain_.
        // Здесь просто используем тот же механизм: ничего не делаем — recvmsgs вернётся.
        // Реальную работу выполняем сразу после recv().
        (void) self;
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
    (void) nl_socket_add_membership(sk_, RTNLGRP_IPV4_ROUTE);
    (void) nl_socket_add_membership(sk_, RTNLGRP_IPV6_ROUTE);

    // Не блокируемся навечно: неблокирующий сокет + периодический опрос
    nl_socket_set_nonblocking(sk_);

    // Коллбек на валидные сообщения (нам не важно содержание — после каждого события пересчитаем WAN)
    nl_socket_modify_cb(sk_, NL_CB_VALID, NL_CB_CUSTOM, &on_nl_valid, this);

    // Запускаем рабочий поток
    th_ = std::thread([this] { ThreadMain_(); });
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
    RecomputeAndApply_();

    using namespace std::chrono_literals;
    while (!stop_.load(std::memory_order_relaxed))
    {
        // Считать все доступные события (не блокируясь навечно)
        (void) nl_recvmsgs_default(sk_);

        // После чтения пакетов — попытаться пересчитать WAN и, если изменились, применить
        RecomputeAndApply_();

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
            changed = true;
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
        (void) NetConfig::nft_apply(cmd4);
        if (wan4 && !p.nat44_src.empty())
        {
            (void) NetConfig::ensure_nat44(*wan4, p.nat44_src); // уже идемпотентно
        }
    }
    {
        // ip6
        std::string cmd6;
        cmd6  = "add table ip6 flowforge_nat\n";
        cmd6 += "add chain ip6 flowforge_nat postrouting { type nat hook postrouting priority 100 ; policy accept; }\n";
        cmd6 += "flush chain ip6 flowforge_nat postrouting\n";
        (void) NetConfig::nft_apply(cmd6);
        if (wan6 && !p.nat66_src.empty())
        {
            (void) NetConfig::ensure_nat66(*wan6, p.nat66_src); // уже идемпотентно
        }
    }

    // 2) MSS clamp: чистим и добавляем заново (как в Network.cpp)
    {
        // Шаг 1: гарантируем table/chain с ЧИСЛОВЫМ приоритетом (совместимо со старыми nft)
        std::string mk;
        mk  = "add table inet flowforge_post\n";
        mk += "add chain inet flowforge_post postrouting "
              "{ type filter hook postrouting priority -150; policy accept; }\n";
        if (!NetConfig::nft_apply(mk)) {
            // fallback: удалить и создать заново
            (void) NetConfig::nft_apply("delete table inet flowforge_post\n");
            (void) NetConfig::nft_apply(mk);
        }
        // Шаг 2: отдельный flush (старые nft падают, если делать всё одним батчем)
        if (!NetConfig::nft_apply("flush chain inet flowforge_post postrouting\n")) {
            (void) NetConfig::nft_apply("delete table inet flowforge_post\n");
            (void) NetConfig::nft_apply(mk);
        }
        // Шаг 3: добавляем правила (сначала современный синтаксис, затем фоллбэк)
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
                // Фоллбэк: фиксированное MSS из MTU (совместимо со старыми nft/ядрами)
                const int mss4 = std::max(536, p.mtu - 40); // IPv4: 20 IP + 20 TCP
                const int mss6 = std::max(536, p.mtu - 60); // IPv6: 40 IP + 20 TCP
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
                (void) NetConfig::nft_apply(rules_fix);
            }
        }

    }
}
