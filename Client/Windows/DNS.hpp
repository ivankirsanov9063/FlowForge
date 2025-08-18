#pragma once
// DnsConfig.hpp — Windows DNS setup (IPv4 + IPv6)
// Требуются: <windows.h>, <iphlpapi.h>, линковка iphlpapi.lib

#include <string>
#include <vector>

#include <windows.h>
#include <iphlpapi.h>

namespace dns
{

    /**
     * @brief Устанавливает список DNS-серверов для интерфейса по NET_LUID.
     * @param luid     Идентификатор сетевого интерфейса (NET_LUID).
     * @param servers  Список адресов DNS в текстовом виде (IPv4/IPv6). Первый — primary.
     * @param suffix   Зарезервировано; в текущей реализации игнорируется.
     * @return true, если операция выполнена успешно; иначе false.
     */
    bool Dns_Set(NET_LUID luid,
                 const std::vector<std::wstring> &servers,
                 const std::wstring &suffix = L"") noexcept;

    /**
     * @brief Сбрасывает DNS-настройки интерфейса.
     * @param luid  Идентификатор сетевого интерфейса (NET_LUID).
     * @return true при успешном возврате к авто-настройке/DHCP (где возможно); иначе false.
     */
    bool Dns_Unset(NET_LUID luid) noexcept;

    /**
     * @brief Возвращает текст последней ошибки.
     * @return Строка с описанием ошибки или пустая строка, если ошибок не было.
     */
    std::wstring Dns_LastError();

} // namespace dns
