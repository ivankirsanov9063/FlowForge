#pragma once
// DnsConfig.hpp — Windows DNS setup via netsh (IPv4 + IPv6)
// Требуются: <windows.h>, <iphlpapi.h>, линковка iphlpapi.lib

#include <string>
#include <vector>
#include <windows.h>
#include <iphlpapi.h>

namespace dns {

    // Установить DNS-серверы для интерфейса по NET_LUID.
    // servers: список IPv4/IPv6 адресов в текстовом виде (первый — primary).
    // suffix: пока игнорируется (см. комментарий в .cpp).
    bool Dns_Set(NET_LUID luid,
                 const std::vector<std::wstring>& servers,
                 const std::wstring& suffix = L"") noexcept;

    // Сбросить DNS (удалить все статические DNS, вернуть авто-настройку/DHCP где возможно).
    bool Dns_Unset(NET_LUID luid) noexcept;

    // Последняя текстовая ошибка (exit code netsh / Win32 last-error).
    std::wstring Dns_LastError();

} // namespace dns
