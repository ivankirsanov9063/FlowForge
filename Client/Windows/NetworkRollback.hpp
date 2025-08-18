#pragma once
// NetworkRollback — безопасный откат сетевых правок VPN-клиента (Windows 7+)

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

#include <iphlpapi.h>
#include <netioapi.h>
#include <string>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace netrb
{

struct Baseline
{
    NET_LUID luid{};     // интерфейс TUN (Wintun)
    bool     haveV4 = false;
    bool     haveV6 = false;

    // то, что было ДО настройки
    BOOL  v4AutoMetric = TRUE;
    ULONG v4Metric     = 0;
    ULONG v4Mtu        = 0;

    BOOL  v6AutoMetric = TRUE;
    ULONG v6Metric     = 0;
    ULONG v6Mtu        = 0;
};

/**
 * @brief Снимает срез состояния интерфейса (метрики/MTU) до изменений.
 * @param ifLuid NET_LUID интерфейса.
 * @param out [out] Заполняемая структура Baseline.
 * @return true, если удалось сохранить хотя бы одно семейство (v4 или v6).
 */
bool CaptureBaseline(const NET_LUID &ifLuid,
                     Baseline &out) noexcept;

/**
 * @brief Восстанавливает метрики/MTU по сохранённому слепку.
 * @param b Сохранённый Baseline.
 * @return true при успешном восстановлении.
 */
bool RestoreBaseline(const Baseline &b) noexcept;

/**
 * @brief Удаляет split-default маршруты (/1) на интерфейсе (v4 и v6).
 * @param ifLuid NET_LUID интерфейса.
 * @return true, если удалены маршруты хотя бы одного семейства.
 */
bool RemoveSplitDefaults(const NET_LUID &ifLuid) noexcept;

/**
 * @brief Удаляет пин-маршрут до сервера (v4 /32 или v6 /128) с Protocol=MIB_IPPROTO_NETMGMT.
 * @param serverIp Строка IP адреса сервера (IPv4 или IPv6).
 * @return true при успешном удалении.
 */
bool RemovePinnedRouteToServer(const char *serverIp) noexcept;

/**
 * @brief Комбинированный откат: снимает split-default, удаляет пин и возвращает метрики/MTU.
 * @param b Сохранённый Baseline.
 * @param serverIp IP адрес сервера (может быть nullptr).
 * @return true при успехе всех шагов.
 */
bool RollbackAll(const Baseline &b,
                 const char *serverIp) noexcept;

} // namespace netrb
