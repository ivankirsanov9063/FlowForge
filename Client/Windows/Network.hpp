#pragma once

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601 // Windows 7+
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

// Порядок важен: winsock2/ws2tcpip перед windows.h
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <winternl.h>
#include <iptypes.h>
#include <netioapi.h>
#include <iphlpapi.h>

#include <optional>
#include <cstdint>
#include <string>
#include <cstring>
#include <cstdio>

#include "TUN.hpp"

// ---------- helpers ----------

namespace Network
{

/**
 * @brief Ищет лучший IPv4 default-маршрут, исключая указанный интерфейс.
 * @param exclude Интерфейс (NET_LUID), который нужно исключить.
 * @return Найденная строка маршрута или std::nullopt.
 */
std::optional<MIB_IPFORWARD_ROW2> fallback_default_route_excluding(const NET_LUID &exclude);

/**
 * @brief Ищет лучший IPv6 default-маршрут, исключая указанный интерфейс.
 * @param exclude Интерфейс (NET_LUID), который нужно исключить.
 * @return Найденная строка маршрута или std::nullopt.
 */
std::optional<MIB_IPFORWARD_ROW2> fallback_default_route6_excluding(const NET_LUID &exclude);

// ---------- IPv6 ----------

/**
 * @brief Парсит IPv6-адрес из строки.
 * @param s Строка-адрес.
 * @param out Результирующий IN6_ADDR.
 * @return true при успехе.
 */
bool ipv6_from_string(const char *s, IN6_ADDR &out);

/**
 * @brief Добавляет/обновляет IPv6-адрес на интерфейсе.
 * @param ifLuid Интерфейс.
 * @param ip IPv6-адрес.
 * @param prefixLen Длина префикса.
 * @return true при успехе.
 */
bool add_ipv6_address_on_if(const NET_LUID &ifLuid,
                            const char *ip,
                            UINT8 prefixLen);

/**
 * @brief Устанавливает метрику интерфейса для IPv6.
 * @param ifLuid Интерфейс.
 * @param metric Метрика.
 * @return true при успехе.
 */
bool set_if_metric_ipv6(const NET_LUID &ifLuid, ULONG metric);

/**
 * @brief Устанавливает MTU интерфейса для IPv6.
 * @param ifLuid Интерфейс.
 * @param mtu MTU.
 * @return true при успехе.
 */
bool set_if_mtu_ipv6(const NET_LUID &ifLuid, ULONG mtu);

/**
 * @brief Добавляет on-link маршрут до IPv6-хоста (/128).
 * @param ifLuid Интерфейс.
 * @param host IPv6-адрес хоста.
 * @param metric Метрика (по умолчанию 1).
 * @return true при успехе.
 */
bool add_onlink_host_route6(const NET_LUID &ifLuid,
                            const char *host,
                            ULONG metric = 1);

/**
 * @brief Возвращает лучший маршрут до IPv6-адреса.
 * @param dest_ip6 Целевой IPv6-адрес.
 * @return Строка маршрута или std::nullopt.
 */
std::optional<MIB_IPFORWARD_ROW2> get_best_route_to6(const char *dest_ip6);

/**
 * @brief Добавляет/обновляет маршрут /128 до хоста через указанный маршрут.
 * @param host6 Целевой IPv6-хост.
 * @param via Существующий маршрут, через который пиновать.
 * @param metric Метрика (по умолчанию 1).
 * @return Код Win32 (NO_ERROR при успехе).
 */
DWORD add_or_update_host_route_via6(const char *host6,
                                    const MIB_IPFORWARD_ROW2 &via,
                                    ULONG metric = 1);

/**
 * @brief Добавляет on-link маршрут по префиксу IPv6.
 * @param ifLuid Интерфейс.
 * @param prefix Префикс IPv6.
 * @param prefixLen Длина префикса.
 * @param metric Метрика.
 * @return true при успехе.
 */
bool add_onlink_route_v6(const NET_LUID &ifLuid,
                         const char *prefix,
                         UINT8 prefixLen,
                         ULONG metric);

// ---------- IPv4 ----------

/**
 * @brief Парсит IPv4-адрес из строки.
 * @param s Строка-адрес.
 * @param out Результирующий IN_ADDR.
 * @return true при успехе.
 */
bool ipv4_from_string(const char *s, IN_ADDR &out);

/**
 * @brief Добавляет/обновляет IPv4-адрес на интерфейсе.
 * @param ifLuid Интерфейс.
 * @param ip IPv4-адрес.
 * @param prefixLen Длина префикса.
 * @return true при успехе.
 */
bool add_ipv4_address_on_if(const NET_LUID &ifLuid,
                            const char *ip,
                            UINT8 prefixLen);

/**
 * @brief Добавляет on-link маршрут до IPv4-хоста (/32).
 * @param ifLuid Интерфейс.
 * @param host IPv4-адрес хоста.
 * @param metric Метрика (по умолчанию 1).
 * @return true при успехе.
 */
bool add_onlink_host_route(const NET_LUID &ifLuid,
                           const char *host,
                           ULONG metric = 1);

/**
 * @brief Возвращает лучший маршрут до IPv4-адреса.
 * @param dest_ip Целевой IPv4-адрес.
 * @return Строка маршрута или std::nullopt.
 */
std::optional<MIB_IPFORWARD_ROW2> get_best_route_to(const char *dest_ip);

/**
 * @brief Добавляет/обновляет маршрут /32 до хоста через указанный маршрут.
 * @param host Целевой IPv4-хост.
 * @param via Существующий маршрут, через который пиновать.
 * @param metric Метрика (по умолчанию 1).
 * @return Код Win32 (NO_ERROR при успехе).
 */
DWORD add_or_update_host_route_via(const char *host,
                                   const MIB_IPFORWARD_ROW2 &via,
                                   ULONG metric = 1);

/**
 * @brief Устанавливает метрику интерфейса для IPv4.
 * @param ifLuid Интерфейс.
 * @param metric Метрика.
 * @return true при успехе.
 */
bool set_if_metric_ipv4(const NET_LUID &ifLuid, ULONG metric);

/**
 * @brief Устанавливает MTU интерфейса для IPv4.
 * @param ifLuid Интерфейс.
 * @param mtu MTU.
 * @return true при успехе.
 */
bool set_if_mtu_ipv4(const NET_LUID &ifLuid, ULONG mtu);

/**
 * @brief Добавляет on-link маршрут по префиксу IPv4.
 * @param ifLuid Интерфейс.
 * @param prefix Префикс IPv4.
 * @param prefixLen Длина префикса.
 * @param metric Метрика.
 * @return true при успехе.
 */
bool add_onlink_route_v4(const NET_LUID &ifLuid,
                         const char *prefix,
                         UINT8 prefixLen,
                         ULONG metric);

// ---------- phases ----------

/**
 * @brief Базовая настройка интерфейса Wintun (IP, MTU, метрики).
 * @param adapter Хэндл адаптера Wintun.
 * @return 0 при успехе, иначе код ошибки.
 */
int ConfigureNetwork_Base(WINTUN_ADAPTER_HANDLE adapter);

/**
 * @brief Пинуeт маршрут до сервера (v4 /32 или v6 /128) вне VPN-интерфейса.
 * @param adapter Хэндл адаптера Wintun.
 * @param server_ip IP-адрес сервера.
 * @return true при успехе.
 */
bool ConfigureNetwork_PinServer(WINTUN_ADAPTER_HANDLE adapter,
                                const std::string &server_ip);

/**
 * @brief Активирует split-default маршруты через VPN peer.
 * @param adapter Хэндл адаптера Wintun.
 * @return true если хотя бы семейство (v4 или v6) успешно активировано.
 */
bool ConfigureNetwork_ActivateDefaults(WINTUN_ADAPTER_HANDLE adapter);

/**
 * @brief Добавляет маршрут по префиксу IPv4 через указанный gateway.
 * @param ifLuid Интерфейс.
 * @param prefix Префикс сети.
 * @param prefixLen Длина префикса.
 * @param gateway_ip IPv4 шлюза.
 * @param metric Метрика.
 * @return true при успехе.
 */
bool add_route_via_gateway_v4(const NET_LUID &ifLuid,
                              const char *prefix,
                              UINT8 prefixLen,
                              const char *gateway_ip,
                              ULONG metric);

/**
 * @brief Добавляет маршрут по префиксу IPv6 через указанный gateway.
 * @param ifLuid Интерфейс.
 * @param prefix Префикс сети.
 * @param prefixLen Длина префикса.
 * @param gateway_ip6 IPv6 шлюза.
 * @param metric Метрика.
 * @return true при успехе.
 */
bool add_route_via_gateway_v6(const NET_LUID &ifLuid,
                              const char *prefix,
                              UINT8 prefixLen,
                              const char *gateway_ip6,
                              ULONG metric);

}
