// DNS.cpp — шапка ДОЛЖНА выглядеть примерно так:

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601 // Win7+
#endif
#define _WINSOCKAPI_ // страховка: запретит попадание winsock.h через windows.h

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <objbase.h>
#include <string>
#include <vector>

#include "DNS.hpp" // ← ТОЛЬКО здесь, после winsock2/ws2tcpip/windows

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Ole32.lib")

namespace
{

std::wstring g_last_err;

void set_err(const std::wstring &msg)
{
    g_last_err = msg;
}

void set_err_win(const std::wstring &msg,
                 DWORD code)
{
    g_last_err = msg + L", Win32=" + std::to_wstring(code);
}

bool is_ipv4(const std::wstring &s)
{
    IN_ADDR a{};
    return InetPtonW(AF_INET, s.c_str(), &a) == 1;
}

bool is_ipv6(const std::wstring &s)
{
    IN6_ADDR a{};
    return InetPtonW(AF_INET6, s.c_str(), &a) == 1;
}

bool luid_to_guid_string(const NET_LUID &luid,
                         std::wstring &guid_str)
{
    GUID guid{};
    if (ConvertInterfaceLuidToGuid(&luid, &guid) != NO_ERROR)
    {
        set_err(L"ConvertInterfaceLuidToGuid failed");
        return false;
    }

    wchar_t buf[64]{};
    const int n = StringFromGUID2(guid, buf, static_cast<int>(std::size(buf)));
    if (n <= 0)
    {
        set_err(L"StringFromGUID2 failed");
        return false;
    }

    guid_str.assign(buf);
    return !guid_str.empty();
}

std::wstring join_comma(const std::vector<std::wstring> &addrs)
{
    std::wstring out;
    out.reserve(64 * addrs.size());
    for (std::size_t i = 0; i < addrs.size(); ++i)
    {
        if (i)
        {
            out.push_back(L',');
        }
        out.append(addrs[i]);
    }
    return out;
}

bool open_interface_key(const std::wstring &base_path,
                        const std::wstring &guid_str,
                        REGSAM access,
                        HKEY &hkey_out)
{
    hkey_out = nullptr;

    std::wstring path = base_path;
    path += guid_str;

    // Открываем существующий ключ (создавать ключ интерфейса нельзя).
    const LSTATUS st = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                                     path.c_str(),
                                     0,
                                     access | KEY_WOW64_64KEY,
                                     &hkey_out);
    if (st != ERROR_SUCCESS)
    {
        set_err_win(L"RegOpenKeyExW failed for " + path, static_cast<DWORD>(st));
        return false;
    }
    return true;
}

bool write_name_server(HKEY hkey,
                       const std::wstring &value) // пустая строка => удалить
{
    if (value.empty())
    {
        const LSTATUS del = RegDeleteValueW(hkey, L"NameServer");
        if (del == ERROR_SUCCESS || del == ERROR_FILE_NOT_FOUND)
        {
            return true;
        }
        set_err_win(L"RegDeleteValueW(NameServer) failed", static_cast<DWORD>(del));
        return false;
    }

    // REG_SZ, UTF-16, включая завершающий нуль
    const DWORD bytes = static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t));
    const LSTATUS st = RegSetValueExW(hkey,
                                      L"NameServer",
                                      0,
                                      REG_SZ,
                                      reinterpret_cast<const BYTE *>(value.c_str()),
                                      bytes);
    if (st != ERROR_SUCCESS)
    {
        set_err_win(L"RegSetValueExW(NameServer) failed", static_cast<DWORD>(st));
        return false;
    }
    return true;
}

void flush_resolver_cache()
{
    using PFN_Flush = BOOL(WINAPI *)(VOID);
    HMODULE dnsapi = LoadLibraryW(L"dnsapi.dll");
    if (!dnsapi)
    {
        return;
    }
    auto p_flush = reinterpret_cast<PFN_Flush>(GetProcAddress(dnsapi, "DnsFlushResolverCache"));
    if (p_flush)
    {
        (void)p_flush();
    }
    FreeLibrary(dnsapi);
}

bool set_dns_for_family(const std::wstring &guid_str,
                        int af,
                        const std::vector<std::wstring> &servers)
{
    if (servers.empty())
    {
        return true;
    }

    const std::wstring value = join_comma(servers);
    const std::wstring base = (af == AF_INET)
                                  ? L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\"
                                  : L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\";

    HKEY hkey = nullptr;
    if (!open_interface_key(base, guid_str, KEY_SET_VALUE, hkey))
    {
        return false;
    }

    const bool ok = write_name_server(hkey, value);
    RegCloseKey(hkey);
    return ok;
}

bool unset_dns_for_family(const std::wstring &guid_str,
                          int af)
{
    const std::wstring base = (af == AF_INET)
                                  ? L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\"
                                  : L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\";

    HKEY hkey = nullptr;
    if (!open_interface_key(base, guid_str, KEY_SET_VALUE, hkey))
    {
        return false;
    }

    const bool ok = write_name_server(hkey, L""); // удаляем NameServer => возврат к DHCP/автонастройке
    RegCloseKey(hkey);
    return ok;
}

} // namespace

namespace DNS
{

bool Dns_Set(NET_LUID luid,
             const std::vector<std::wstring> &servers,
             const std::wstring &/*suffix*/) noexcept
{
    g_last_err.clear();

    if (servers.empty())
    {
        set_err(L"servers is empty");
        return false;
    }

    std::vector<std::wstring> v4;
    std::vector<std::wstring> v6;
    v4.reserve(servers.size());
    v6.reserve(servers.size());

    for (const auto &s : servers)
    {
        if (is_ipv4(s))
        {
            v4.push_back(s);
        }
        else if (is_ipv6(s))
        {
            v6.push_back(s);
        }
        else
        {
            set_err(L"Invalid IP address: " + s);
            return false;
        }
    }

    std::wstring guid_str;
    if (!luid_to_guid_string(luid, guid_str))
    {
        return false;
    }

    if (!set_dns_for_family(guid_str, AF_INET, v4))
    {
        return false;
    }
    if (!set_dns_for_family(guid_str, AF_INET6, v6))
    {
        return false;
    }

    flush_resolver_cache();
    return true;
}

bool Dns_Unset(NET_LUID luid) noexcept
{
    g_last_err.clear();

    std::wstring guid_str;
    if (!luid_to_guid_string(luid, guid_str))
    {
        return false;
    }

    const bool ok4 = unset_dns_for_family(guid_str, AF_INET);
    const bool ok6 = unset_dns_for_family(guid_str, AF_INET6);

    flush_resolver_cache();
    return ok4 && ok6;
}

std::wstring Dns_LastError()
{
    return g_last_err;
}

} // namespace DNS
