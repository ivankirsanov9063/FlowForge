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

#include <winsock2.h>     // обязательно раньше windows.h
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <string>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace netrb {

    struct Baseline {
        NET_LUID luid{};         // интерфейс TUN (Wintun)
        bool haveV4 = false;
        bool haveV6 = false;

        // то, что было ДО настройки
        BOOL  v4AutoMetric = TRUE;
        ULONG v4Metric     = 0;
        ULONG v4Mtu        = 0;

        BOOL  v6AutoMetric = TRUE;
        ULONG v6Metric     = 0;
        ULONG v6Mtu        = 0;
    };

    // Снять срез состояния интерфейса до изменения (метрики/MTU).
    bool CaptureBaseline(const NET_LUID& ifLuid, Baseline& out) noexcept;

    // Вернуть метрики/MTU как было (по сохранённому Baseline).
    bool RestoreBaseline(const Baseline& b) noexcept;

    // Удалить split-default маршруты (/1) на заданном интерфейсе (v4+v6).
    bool RemoveSplitDefaults(const NET_LUID& ifLuid) noexcept;

    // Удалить пин-маршрут до сервера (v4 /32 или v6 /128), который мы ставили.
    // Ищется маршрут с Protocol = MIB_IPPROTO_NETMGMT (наш маркер).
    bool RemovePinnedRouteToServer(const char* serverIp) noexcept;

    // Комбо: безопасный откат всего (split-defaults + пин + метрики/MTU).
    bool RollbackAll(const Baseline& b, const char* serverIp) noexcept;

} // namespace netrb
