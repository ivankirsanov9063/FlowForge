#pragma once

#include "Network.hpp"

#include <string>
#include <optional>
#include <thread>
#include <atomic>
#include <mutex>

/**
 * @file NetWatcher.hpp
 * @brief Вотчер за изменениями default route и пересборкой NAT/MSS.
 *
 * Класс отслеживает netlink-события RTNLGRP_IPV4_ROUTE / RTNLGRP_IPV6_ROUTE.
 * На каждое изменение маршрута по умолчанию:
 *  - вычисляет WAN-интерфейсы для AF_INET/AF_INET6 (через NetConfig::find_default_oifname),
 *  - идемпотентно пересоздаёт NAT44/NAT66 (через NetConfig::ensure_nat44/ensure_nat66),
 *  - идемпотентно пересоздаёт MSS clamp (через nft-команды в собственной цепочке).
 *
 * Ошибки инициализации выбрасываются как std::runtime_error.
 * Деструктор останавливает внутренний поток.
 */
class NetWatcher
{
public:
    /**
     * @brief Конструктор: запускает вотчер.
     * @param params Параметры NAT (CIDR источника для v4/v6 и прочее).
     * @throws std::runtime_error при ошибке инициализации netlink.
     */
    explicit NetWatcher(const NetConfig::Params &params = NetConfig::Params{});

    /**
     * @brief Деструктор: корректно останавливает поток.
     */
    ~NetWatcher();

    /**
     * @brief Последний известный WAN-интерфейс для IPv4.
     * @return Имя интерфейса или std::nullopt.
     */
    std::optional<std::string> Wan4() const;

    /**
     * @brief Последний известный WAN-интерфейс для IPv6.
     * @return Имя интерфейса или std::nullopt.
     */
    std::optional<std::string> Wan6() const;

private:
    /**
     * @brief Копия параметров конфигурации (CIDR для NAT и т.п.).
     */
    NetConfig::Params params_;

    /**
     * @brief NETLINK_ROUTE сокет (libnl).
     */
    nl_sock *sk_ = nullptr;

    /**
     * @brief Флаг завершения рабочего потока.
     */
    std::atomic<bool> stop_{false};

    /**
     * @brief Рабочий поток, ожидающий события netlink.
     */
    std::thread th_;

    /**
     * @brief Мьютекс для доступа к last_wan4_/last_wan6_.
     */
    mutable std::mutex mu_;

    /**
     * @brief Последний обнаруженный WAN-интерфейс для IPv4.
     */
    std::optional<std::string> last_wan4_;

    /**
     * @brief Последний обнаруженный WAN-интерфейс для IPv6.
     */
    std::optional<std::string> last_wan6_;

    /**
     * @brief Основная функция потока: принимает события и реагирует.
     */
    void ThreadMain_();

    /**
     * @brief Пересчитать WAN-интерфейсы и применить NAT/MSS, если изменились.
     */
    void RecomputeAndApply_();

    /**
     * @brief Идемпотентно применяет NAT и MSS clamp для заданных WAN-интерфейсов.
     *        При отсутствии WAN интерфейса — соответствующая цепь очищается.
     * @param wan4 Имя WAN для IPv4 (или nullopt).
     * @param wan6 Имя WAN для IPv6 (или nullopt).
     */
    static void ApplyNatAndMss_(const std::optional<std::string> &wan4,
                                const std::optional<std::string> &wan6,
                                const NetConfig::Params          &p);
};
