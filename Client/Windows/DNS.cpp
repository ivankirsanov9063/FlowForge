// DNS.cpp — реализация RAII-класса настройки DNS через реестр

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601 // Windows 7+
#endif

// Порядок критичен для WinSock/WinAPI:
#include <winsock2.h>   // до windows.h
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <objbase.h>
#include <stringapiset.h>

#include <string>
#include <vector>
#include <stdexcept>

#include "DNS.hpp"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Ole32.lib")

// ===== helpers =====

[[noreturn]] void DNS::Throw(const std::string &msg_utf8)
{
    throw std::runtime_error(msg_utf8);
}

[[noreturn]] void DNS::ThrowWin(const std::string &prefix_utf8,
                                DWORD              code)
{
    std::string m = prefix_utf8;
    m += " (Win32=";
    m += std::to_string(code);
    m += ")";
    throw std::runtime_error(m);
}

std::string DNS::Utf8(const std::wstring &ws)
{
    if (ws.empty())
    {
        return std::string();
    }
    int len = ::WideCharToMultiByte(CP_UTF8, 0, ws.c_str(),
                                    static_cast<int>(ws.size()),
                                    nullptr, 0, nullptr, nullptr);
    if (len <= 0)
    {
        ThrowWin("WideCharToMultiByte(size) failed", GetLastError());
    }
    std::string out;
    out.resize(len);
    len = ::WideCharToMultiByte(CP_UTF8, 0, ws.c_str(),
                                static_cast<int>(ws.size()),
                                out.data(), len, nullptr, nullptr);
    if (len <= 0)
    {
        ThrowWin("WideCharToMultiByte(copy) failed", GetLastError());
    }
    return out;
}

bool DNS::IsIPv4(const std::wstring &s) noexcept
{
    IN_ADDR a{};
    return InetPtonW(AF_INET, s.c_str(), &a) == 1;
}

bool DNS::IsIPv6(const std::wstring &s) noexcept
{
    IN6_ADDR a{};
    return InetPtonW(AF_INET6, s.c_str(), &a) == 1;
}

std::wstring DNS::JoinComma(const std::vector<std::wstring> &list)
{
    std::wstring out;
    out.reserve(32 * list.size());
    for (size_t i = 0; i < list.size(); ++i)
    {
        if (i)
        {
            out.push_back(L',');
        }
        out.append(list[i]);
    }
    return out;
}

void DNS::LuidToGuidString(std::wstring &out)
{
    GUID guid{};
    if (ConvertInterfaceLuidToGuid(&luid_, &guid) != NO_ERROR)
    {
        Throw("ConvertInterfaceLuidToGuid failed");
    }

    wchar_t buf[64]{};
    const int n = StringFromGUID2(guid, buf, static_cast<int>(std::size(buf)));
    if (n <= 0)
    {
        Throw("StringFromGUID2 failed");
    }
    out.assign(buf);
    if (out.empty())
    {
        Throw("Empty GUID string");
    }
}

void DNS::OpenInterfaceKey(const std::wstring &base_path,
                           const std::wstring &guid_str,
                           REGSAM              access,
                           HKEY               &hkey_out)
{
    hkey_out = nullptr;
    std::wstring path = base_path;
    path += guid_str;

    const LSTATUS st = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                                     path.c_str(),
                                     0,
                                     access | KEY_WOW64_64KEY,
                                     &hkey_out);
    if (st != ERROR_SUCCESS)
    {
        ThrowWin("RegOpenKeyExW failed: " + Utf8(path), static_cast<DWORD>(st));
    }
}

void DNS::WriteNameServer(HKEY                hkey,
                          const std::wstring &value)
{
    if (value.empty())
    {
        const LSTATUS del = RegDeleteValueW(hkey, L"NameServer");
        if (del == ERROR_SUCCESS || del == ERROR_FILE_NOT_FOUND)
        {
            return;
        }
        ThrowWin("RegDeleteValueW(NameServer) failed", static_cast<DWORD>(del));
    }
    else
    {
        const DWORD bytes = static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t));
        const LSTATUS st  = RegSetValueExW(hkey,
                                           L"NameServer",
                                           0,
                                           REG_SZ,
                                           reinterpret_cast<const BYTE *>(value.c_str()),
                                           bytes);
        if (st != ERROR_SUCCESS)
        {
            ThrowWin("RegSetValueExW(NameServer) failed", static_cast<DWORD>(st));
        }
    }
}

void DNS::ReadNameServer(const std::wstring &base_path,
                         std::wstring       &out_value,
                         bool               &present)
{
    present = false;
    out_value.clear();

    HKEY hkey = nullptr;
    OpenInterfaceKey(base_path, guid_str_, KEY_QUERY_VALUE, hkey);

    DWORD  type  = 0;
    DWORD  bytes = 0;
    LSTATUS st   = RegQueryValueExW(hkey, L"NameServer", nullptr, &type, nullptr, &bytes);
    if (st == ERROR_FILE_NOT_FOUND)
    {
        RegCloseKey(hkey);
        present = false;
        return;
    }
    if (st != ERROR_SUCCESS || type != REG_SZ || bytes == 0)
    {
        RegCloseKey(hkey);
        ThrowWin("RegQueryValueExW(NameServer) failed", static_cast<DWORD>(st));
    }

    std::wstring buf;
    buf.resize(bytes / sizeof(wchar_t));
    st = RegQueryValueExW(hkey,
                          L"NameServer",
                          nullptr,
                          &type,
                          reinterpret_cast<LPBYTE>(buf.data()),
                          &bytes);
    RegCloseKey(hkey);
    if (st != ERROR_SUCCESS || type != REG_SZ)
    {
        ThrowWin("RegQueryValueExW(NameServer #2) failed", static_cast<DWORD>(st));
    }

    if (!buf.empty() && buf.back() == L'\0')
    {
        buf.pop_back();
    }

    out_value = std::move(buf);
    present   = true;
}

std::wstring DNS::BasePathForAf(int af) const
{
    return (af == AF_INET)
               ? L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\"
               : L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\";
}

void DNS::SetForFamily(int                              af,
                       const std::vector<std::wstring> &servers)
{
    if (servers.empty())
    {
        return;
    }

    const std::wstring value = JoinComma(servers);
    const std::wstring base  = BasePathForAf(af);

    HKEY hkey = nullptr;
    OpenInterfaceKey(base, guid_str_, KEY_SET_VALUE, hkey);
    WriteNameServer(hkey, value);
    RegCloseKey(hkey);
}

void DNS::UnsetForFamily(int af)
{
    const std::wstring base = BasePathForAf(af);

    HKEY hkey = nullptr;
    OpenInterfaceKey(base, guid_str_, KEY_SET_VALUE, hkey);
    WriteNameServer(hkey, L"");
    RegCloseKey(hkey);
}

void DNS::FlushResolverCache() noexcept
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

// ===== ctors/dtors =====

DNS::DNS(const NET_LUID &luid) noexcept
{
    luid_ = luid;
}

DNS::~DNS()
{
    try
    {
        Revert();
    }
    catch (...)
    {
        // no-throw
    }
}

DNS::DNS(DNS &&other) noexcept
{
    *this = std::move(other);
}

DNS &DNS::operator=(DNS &&other) noexcept
{
    if (this != &other)
    {
        try
        {
            Revert();
        }
        catch (...)
        {
            // no-throw
        }

        luid_     = other.luid_;
        guid_str_ = std::move(other.guid_str_);
        applied_  = other.applied_;

        prev_v4_present_ = other.prev_v4_present_;
        prev_v6_present_ = other.prev_v6_present_;
        prev_v4_         = std::move(other.prev_v4_);
        prev_v6_         = std::move(other.prev_v6_);
        touched_v4_      = other.touched_v4_;
        touched_v6_      = other.touched_v6_;

        other.applied_         = false;
        other.touched_v4_      = false;
        other.touched_v6_      = false;
        other.prev_v4_present_ = false;
        other.prev_v6_present_ = false;
    }
    return *this;
}

// ===== API =====

void DNS::Apply(const std::vector<std::wstring> &servers)
{
    touched_v4_ = touched_v6_ = false;
    prev_v4_present_ = prev_v6_present_ = false;
    prev_v4_.clear();
    prev_v6_.clear();

    if (servers.empty())
    {
        throw std::invalid_argument("DNS.Apply: servers list is empty");
    }

    if (guid_str_.empty())
    {
        LuidToGuidString(guid_str_);
    }

    std::vector<std::wstring> v4, v6;
    v4.reserve(servers.size());
    v6.reserve(servers.size());
    for (const auto &s : servers)
    {
        if (IsIPv4(s))
        {
            v4.push_back(s);
        }
        else if (IsIPv6(s))
        {
            v6.push_back(s);
        }
        else
        {
            throw std::invalid_argument("DNS.Apply: invalid IP address: " + Utf8(s));
        }
    }

    ReadNameServer(BasePathForAf(AF_INET),  prev_v4_, prev_v4_present_);
    ReadNameServer(BasePathForAf(AF_INET6), prev_v6_, prev_v6_present_);

    if (!v4.empty())
    {
        SetForFamily(AF_INET, v4);
        touched_v4_ = true;
    }
    if (!v6.empty())
    {
        SetForFamily(AF_INET6, v6);
        touched_v6_ = true;
    }

    FlushResolverCache();
    applied_ = true;
}

void DNS::Revert()
{
    if (!applied_)
    {
        return;
    }

    bool any_error = false;

    if (touched_v4_)
    {
        try
        {
            if (prev_v4_present_)
            {
                HKEY hkey = nullptr;
                OpenInterfaceKey(BasePathForAf(AF_INET), guid_str_, KEY_SET_VALUE, hkey);
                WriteNameServer(hkey, prev_v4_);
                RegCloseKey(hkey);
            }
            else
            {
                UnsetForFamily(AF_INET);
            }
        }
        catch (...)
        {
            any_error = true;
        }
    }

    if (touched_v6_)
    {
        try
        {
            if (prev_v6_present_)
            {
                HKEY hkey = nullptr;
                OpenInterfaceKey(BasePathForAf(AF_INET6), guid_str_, KEY_SET_VALUE, hkey);
                WriteNameServer(hkey, prev_v6_);
                RegCloseKey(hkey);
            }
            else
            {
                UnsetForFamily(AF_INET6);
            }
        }
        catch (...)
        {
            any_error = true;
        }
    }

    FlushResolverCache();

    applied_            = false;
    touched_v4_         = false;
    touched_v6_         = false;
    prev_v4_present_    = false;
    prev_v6_present_    = false;
    prev_v4_.clear();
    prev_v6_.clear();

    if (any_error)
    {
        Throw("DNS.Revert: one or more operations failed");
    }
}
