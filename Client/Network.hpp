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

/**
 * @brief Завершает программу с сообщением об ошибке Netlink.
 * @param where Место возникновения ошибки.
 * @param err Код ошибки Netlink.
 */
void die(const char *where, int err);

/**
 * @brief Выводит предупреждение с ошибкой Netlink (игнорируется).
 * @param where Место возникновения ошибки.
 * @param err Код ошибки Netlink.
 */
void warn(const char *where, int err);

/**
 * @brief Проверяет, является ли строка IPv6-адресом.
 * @param s Строка с адресом.
 * @return true, если IPv6, иначе false.
 */
bool is_ipv6_literal(const std::string &s);

/**
 * @brief Удаляет квадратные скобки вокруг IPv6-адреса.
 * @param s Строка с адресом.
 * @return Адрес без скобок.
 */
std::string strip_brackets(std::string s);

/**
 * @brief Устанавливает сетевой интерфейс в состояние UP.
 * @param ifname Имя интерфейса.
 * @return 0 при успехе, отрицательный код ошибки.
 */
int if_set_up(const std::string &ifname);

/**
 * @brief Устанавливает MTU для интерфейса.
 * @param ifname Имя интерфейса.
 * @param mtu Значение MTU.
 * @return 0 при успехе, отрицательный код ошибки.
 */
int if_set_mtu(const std::string &ifname, int mtu);

/**
 * @brief Удаляет все адреса указанного семейства с интерфейса.
 * @param sk Сокет Netlink.
 * @param ifindex Индекс интерфейса.
 * @param family AF_INET или AF_INET6.
 */
void flush_addrs(struct nl_sock *sk, int ifindex, int family);

/**
 * @brief Добавляет P2P-адрес на интерфейс.
 * @param sk Сокет Netlink.
 * @param ifindex Индекс интерфейса.
 * @param family AF_INET или AF_INET6.
 * @param local_str Локальный адрес.
 * @param prefix Префикс.
 * @param peer_str Адрес соседа.
 */
void add_addr_p2p(struct nl_sock *sk, int ifindex, int family,
                         const std::string &local_str, int prefix,
                         const std::string &peer_str);

/**
 * @brief Информация о шлюзе.
 */
struct GwInfo
{
    int         ifindex;  ///< Индекс интерфейса.
    std::string gw_text;  ///< IP-адрес шлюза.
};

/**
 * @brief Ищет шлюз по умолчанию.
 * @param sk Сокет Netlink.
 * @param family AF_INET или AF_INET6.
 * @return Данные о шлюзе, если найден.
 */
std::optional<GwInfo> find_default_gw(struct nl_sock *sk, int family);

/**
 * @brief Получает метрику текущего маршрута по умолчанию.
 * @param sk Сокет Netlink.
 * @param family AF_INET или AF_INET6.
 * @return Метрика, если найдена.
 */
std::optional<int> get_default_metric(struct nl_sock *sk, int family);

/**
 * @brief Добавляет маршрут к хосту через указанный шлюз.
 * @param sk Сокет Netlink.
 * @param family AF_INET или AF_INET6.
 * @param host_ip IP-адрес хоста.
 * @param gw Данные о шлюзе.
 */
void add_host_route_via_gw(struct nl_sock *sk, int family,
                                  const std::string &host_ip,
                                  const GwInfo &gw);

/**
 * @brief Заменяет маршрут по умолчанию на интерфейс.
 * @param sk Сокет Netlink.
 * @param family AF_INET или AF_INET6.
 * @param oif Индекс интерфейса.
 */
void replace_default_via_dev(struct nl_sock *sk, int family, int oif);

/**
 * @brief Записывает строку в файл /proc.
 * @param path Путь к файлу.
 * @param data Строка для записи.
 */
void write_proc(const char *path, const char *data);

/**
 * @brief Записывает значение sysctl для интерфейса.
 * @param ifname Имя интерфейса.
 * @param key Параметр sysctl.
 * @param value Значение.
 */
void write_proc_if_sysctl(const std::string &ifname,
                                 const char       *key,
                                 const char       *value);
