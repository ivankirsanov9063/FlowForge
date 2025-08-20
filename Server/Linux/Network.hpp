// Server/Network.hpp
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <csignal>
#include <optional>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <arpa/inet.h>

namespace NetConfig
{
    /**
     * @brief CIDR блок IPv4.
     */
    struct CidrV4
    {
        std::uint32_t addr_be; ///< Адрес в big-endian.
        std::uint8_t  prefix;  ///< Длина префикса.
    };

    /**
     * @brief CIDR блок IPv6.
     */
    struct CidrV6
    {
        std::array<std::uint8_t, 16> addr; ///< Адрес.
        std::uint8_t                 prefix; ///< Длина префикса.
    };

    /**
     * @brief Параметры конфигурации сервера.
     */
    struct Params
    {
        int mtu = 1400; ///< MTU интерфейса.

        CidrV4       v4_local   { inet_addr("10.8.0.1"), 32 }; ///< Локальный IPv4.
        std::uint32_t v4_peer_be = inet_addr("10.8.0.2"); ///< IPv4 соседа.

        CidrV6 v6_local { /* Локальный IPv6 */ { 0xfd,0x00,0xde,0xad,0xbe,0xef,0,0,0,0,0,0,0,0,0,1 }, 128 };
        std::array<std::uint8_t, 16> v6_peer { /* IPv6 соседа */ { 0xfd,0x00,0xde,0xad,0xbe,0xef,0,0,0,0,0,0,0,0,0,2 } };

        std::string nat44_src = "10.8.0.0/24";     ///< CIDR для NAT44.
        std::string nat66_src = "fd00:dead:beef::/64"; ///< CIDR для NAT66.
    };

    /**
     * @brief Записывает значение в sysctl файл.
     * @param path Путь к файлу.
     * @param val Значение.
     * @return true при успехе.
     */
    bool write_sysctl(const char *path, const char *val);

    /**
     * @brief Записывает значение в sysctl для интерфейса IPv6.
     * @param ifname Имя интерфейса.
     * @param key Ключ sysctl.
     * @param val Значение.
     * @return true при успехе.
     */
    bool write_if_sysctl(const std::string &ifname, const char *key, const char *val);

    /**
     * @brief Создаёт и подключает NETLINK_ROUTE сокет.
     * @return nl_sock* при успехе, nullptr при ошибке.
     */
    nl_sock *nl_connect_route();

    /**
     * @brief Поднимает интерфейс и устанавливает MTU.
     * @param sk Сокет Netlink.
     * @param ifindex Индекс интерфейса.
     * @param mtu MTU.
     * @return true при успехе.
     */
    bool link_set_up_and_mtu(nl_sock *sk, int ifindex, int mtu);

    /**
     * @brief Удаляет все IP-адреса с интерфейса.
     * @param sk Сокет Netlink.
     * @param ifindex Индекс интерфейса.
     * @return true при успехе.
     */
    bool addr_flush_all(nl_sock *sk, int ifindex);

    /**
     * @brief Добавляет IPv4 P2P адрес.
     * @param sk Сокет Netlink.
     * @param ifindex Индекс интерфейса.
     * @param local_be Локальный адрес.
     * @param peer_be Адрес соседа.
     * @param prefix Длина префикса.
     * @return true при успехе или если адрес уже существует.
     */
    bool addr_add_v4_p2p(nl_sock *sk, int ifindex,
                                std::uint32_t local_be,
                                std::uint32_t peer_be,
                                std::uint8_t  prefix);

    /**
     * @brief Добавляет локальный IPv6 адрес.
     * @param sk Сокет Netlink.
     * @param ifindex Индекс интерфейса.
     * @param local Локальный IPv6.
     * @param prefix Длина префикса.
     * @return true при успехе или если адрес уже существует.
     */
    bool addr_add_v6_local(nl_sock *sk, int ifindex,
                                  const std::array<std::uint8_t, 16> &local,
                                  std::uint8_t prefix);

    /**
     * @brief Добавляет маршрут на IPv6-хост через on-link.
     * @param sk Сокет Netlink.
     * @param ifindex Индекс интерфейса.
     * @param dst128 IPv6-адрес назначения /128.
     * @return true при успехе или если маршрут уже существует.
     */
    bool route_add_onlink_host_v6(nl_sock *sk, int ifindex,
                                         const std::array<std::uint8_t, 16> &dst128);

    /**
     * @brief Находит имя интерфейса для маршрута по умолчанию.
     * @param sk Сокет Netlink.
     * @param family AF_INET или AF_INET6.
     * @return Имя интерфейса или std::nullopt.
     */
    std::optional<std::string> find_default_oifname(nl_sock *sk, int family);

    /**
     * @brief Применяет команды nftables.
     * @param commands Команды в виде строки.
     * @return true при успехе или если ошибка не критична.
     */
    bool nft_apply(const std::string &commands);

    /**
     * @brief Настраивает NAT44 для указанного интерфейса.
     * @param oifname Имя интерфейса.
     * @param src_cidr Исходный CIDR.
     * @return true при успехе.
     */
    bool ensure_nat44(const std::string &oifname, const std::string &src_cidr);

    /**
     * @brief Настраивает NAT66 для указанного интерфейса.
     * @param oifname Имя интерфейса.
     * @param src_cidr Исходный CIDR.
     * @return true при успехе.
     */
    bool ensure_nat66(const std::string &oifname, const std::string &src_cidr);

    /**
     * @brief Применяет серверную сетевую конфигурацию.
     * @param ifname Имя интерфейса.
     * @param p Параметры конфигурации (по умолчанию).
     * @return true при успехе.
     */
    bool ApplyServerSide(const std::string &ifname,
                         const Params      &p = Params{},
                         bool with_nat_fw = true);
} // namespace NetConfig
