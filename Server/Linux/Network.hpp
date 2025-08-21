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

        CidrV4       v4_local   { inet_addr("10.8.0.1"), 24 }; ///< Адрес шлюза TUN и префикс пула (без peer).
        CidrV6 v6_local { /* Адрес шлюза TUN */ { 0xfd,0x00,0xde,0xad,0xbe,0xef,0,0,0,0,0,0,0,0,0,1 }, 64 };

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

    /// Добавляет локальный IPv4 адрес с префиксом (без peer).
    bool addr_add_v4_local(nl_sock *sk, int ifindex,
                               std::uint32_t local_be,
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
     * @brief Разобрать строку IPv4 CIDR в структуру CidrV4.
     * @param s Строка формата "A.B.C.D/len". Если "/len" опущен, берётся 32.
     * @param out Куда записать адрес/префикс.
     * @return true при успехе.
     */
    bool parse_cidr4(const std::string &s, CidrV4 &out);

    /**
     * @brief Разобрать строку IPv6 CIDR в структуру CidrV6.
     * @param s Строка формата "xxxx::1/len". Если "/len" опущен, берётся 128.
     * @param out Куда записать адрес/префикс.
     * @return true при успехе.
     */
    bool parse_cidr6(const std::string &s, CidrV6 &out);

    /**
     * @brief Вернуть строку сети вида "A.B.C.D/p" (обнуляя хостовые биты).
     * @param c CIDR IPv4.
     */
    std::string to_network_cidr(const CidrV4 &c);

    /**
     * @brief Вернуть строку сети вида "xxxx::/p" (обнуляя хостовые биты).
     * @param c CIDR IPv6.
     */
    std::string to_network_cidr(const CidrV6 &c);

    /**
     * @brief Находит имя интерфейса для маршрута по умолчанию.
     * @param sk Сокет Netlink.
     * @param family AF_INET или AF_INET6.
     * @return Имя интерфейса или std::nullopt.
     */
    std::optional<std::string> find_default_oifname(nl_sock *sk, int family);

    /**
     * @brief Feature-probe: проверка доступности nftables в рантайме.
     *
     * Пытается выполнить безвредную nft-команду. Если libnftables/ядро
     * не поддерживают nft (или система в режиме iptables-legacy),
     * вернёт false.
     *
     * @return true если nftables доступен для конфигурации.
     */
    bool nft_feature_probe();

    /**
     * @brief Задать политики файрвола для TUN-интерфейса.
     *
     * Создаёт таблицу inet flowforge_fw с цепочками:
     *  - input  (hook input): для iifname==ifname → jump tun_in (policy drop),
     *    где: ct state invalid drop; ct established,related accept;
     *         anti-spoof (ip/ip6 saddr в пуле); лимитируем ICMP/ICMPv6.
     *  - forward (hook forward): для iifname==ifname → jump tun_fwd,
     *    где: anti-spoof; ct invalid drop; ct established,related accept; accept.
     *
     * Идемпотентно: повторные вызовы безопасны.
     *
     * @throws ничего (возвращает false при ошибке).
     */
    bool ensure_fw_tun(const std::string &ifname, const Params &p);

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
     * @brief Применяет серверную сетевую конфигурацию (TUN адресация, форвардинг, NAT/MSS).
     * @param ifname Имя интерфейса.
     * @param p Параметры конфигурации (по умолчанию).
     * @param with_nat_fw Включать ли NAT/MSS/форвардинг.
     * @throws std::runtime_error при любой критичной ошибке применения.
     */
    void ApplyServerSide(const std::string &ifname,
                         const Params      &p = Params{},
                         bool with_nat_fw = true);
} // namespace NetConfig
