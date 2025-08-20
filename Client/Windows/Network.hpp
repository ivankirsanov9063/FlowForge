#pragma once

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
#include <stdexcept>

#include "TUN.hpp"

namespace Network
{

/**
 * @brief Версия IP-стека.
 */
enum class IpVersion
{
    V4, /**< IPv4. */
    V6  /**< IPv6. */
};

/**
 * @brief Устанавливает метрику интерфейса (IPv4/IPv6).
 * @param ifLuid Интерфейс.
 * @param metric Метрика.
 * @param ver    Версия IP.
 * @throw std::runtime_error Ошибка WinAPI.
 */
void set_if_metric(const NET_LUID &ifLuid, ULONG metric, IpVersion ver);

/**
 * @brief Устанавливает MTU интерфейса (IPv4/IPv6).
 * @param ifLuid Интерфейс.
 * @param mtu    MTU.
 * @param ver    Версия IP.
 * @throw std::runtime_error Ошибка WinAPI.
 */
void set_if_mtu(const NET_LUID &ifLuid, ULONG mtu, IpVersion ver);

/**
 * @brief Добавляет/обновляет адрес на интерфейсе (IPv4/IPv6).
 * @param ifLuid    Интерфейс.
 * @param ip        IPv4/IPv6 адрес строкой.
 * @param prefixLen Длина префикса.
 * @param ver       Версия IP.
 * @throw std::invalid_argument Невалидный IP.
 * @throw std::runtime_error    Ошибка WinAPI.
 */
void add_ip_address_on_if(const NET_LUID &ifLuid,
                          const char *ip,
                          UINT8 prefixLen,
                          IpVersion ver);

/**
 * @brief Добавляет on-link маршрут сети (IPv4/IPv6).
 * @param ifLuid    Интерфейс.
 * @param prefix    Префикс сети.
 * @param prefixLen Длина префикса.
 * @param metric    Метрика.
 * @param ver       Версия IP.
 * @throw std::invalid_argument Невалидный префикс.
 * @throw std::runtime_error    Ошибка WinAPI.
 */
void add_onlink_route(const NET_LUID &ifLuid,
                      const char *prefix,
                      UINT8 prefixLen,
                      ULONG metric,
                      IpVersion ver);

/**
 * @brief Добавляет on-link маршрут до хоста (IPv4/IPv6).
 * @param ifLuid Интерфейс.
 * @param ip     IP-адрес хоста.
 * @param metric Метрика.
 * @param ver    Версия IP.
 * @throw std::invalid_argument Невалидный адрес.
 * @throw std::runtime_error    Ошибка WinAPI.
 */
void add_onlink_host_route(const NET_LUID &ifLuid,
                           const char *ip,
                           ULONG metric,
                           IpVersion ver);

/**
 * @brief Находит лучший маршрут до адреса (IPv4/IPv6).
 * @param dest_ip  Назначение.
 * @param ver      Версия IP.
 * @return Маршрут или std::nullopt (если нет).
 * @throw std::invalid_argument Невалидный адрес.
 * @throw std::runtime_error    Ошибка WinAPI.
 */
std::optional<MIB_IPFORWARD_ROW2> get_best_route_to_generic(const char *dest_ip,
                                                            IpVersion ver);

/**
 * @brief Возвращает лучший default-маршрут (0/0 или ::/0), исключая указанный интерфейс.
 * @param exclude Интерфейс (NET_LUID), который нужно исключить.
 * @param ver     Версия IP.
 * @return Найденный маршрут или std::nullopt.
 * @throw std::runtime_error Ошибка WinAPI.
 */
std::optional<MIB_IPFORWARD_ROW2> fallback_default_route_excluding(const NET_LUID &exclude,
                                                                   IpVersion ver);

/**
 * @brief Добавляет/обновляет pinned-маршрут до хоста через заданный route (IPv4/IPv6).
 * @param host   Целевой хост.
 * @param via    Существующая строка маршрута (из GetBestRoute2 или fallback).
 * @param metric Метрика.
 * @param ver    Версия IP.
 * @throw std::invalid_argument Невалидный адрес или несоответствие семейства.
 * @throw std::runtime_error    Ошибка WinAPI.
 */
void add_or_update_host_route_via(const char *host,
                                  const MIB_IPFORWARD_ROW2 &via,
                                  ULONG metric,
                                  IpVersion ver);

/**
 * @brief Добавляет маршрут по префиксу через указанный gateway (IPv4/IPv6).
 * @param ifLuid    Интерфейс.
 * @param prefix    Префикс.
 * @param prefixLen Длина префикса.
 * @param gateway   IP шлюза.
 * @param metric    Метрика.
 * @param ver       Версия IP.
 * @throw std::invalid_argument Невалидные адреса.
 * @throw std::runtime_error    Ошибка WinAPI.
 */
void add_route_via_gateway(const NET_LUID &ifLuid,
                           const char *prefix,
                           UINT8 prefixLen,
                           const char *gateway,
                           ULONG metric,
                           IpVersion ver);

/**
 * @brief Полная настройка сети для одного семейства: Base → PinServer → ActivateDefaults.
 *        Если pin не удался (нет маршрута до сервера), split-default для этого семейства не активируется.
 * @param adapter  Хэндл адаптера Wintun.
 * @param server_ip IP-адрес сервера (IPv4/IPv6 строкой).
 * @param ver      Какое семейство настраивать.
 * @throw std::invalid_argument Невалидные аргументы.
 * @throw std::runtime_error    Ошибки WinAPI/настройки.
 */
void ConfigureNetwork(WINTUN_ADAPTER_HANDLE adapter,
                      const std::string &server_ip,
                      IpVersion ver);

/**
 * @brief Параметры адресного плана интерфейса VPN.
 *        Значения совпадают с прежними дефолтами, если не переопределять.
 */
struct AddressPlan
{
    std::string local4 = "10.8.0.2";
    std::string peer4  = "10.8.0.1";
    std::string local6 = "fd00:dead:beef::2";
    std::string peer6  = "fd00:dead:beef::1";
    unsigned long mtu  = 1400;
};

/**
 * @brief Задать адресный план (локальные/peer-адреса и MTU).
 *        Можно вызывать до ConfigureNetwork().
 * @throw std::invalid_argument При некорректных адресах/MTU.
 */
void SetAddressPlan(const AddressPlan &plan);

} // namespace Network
