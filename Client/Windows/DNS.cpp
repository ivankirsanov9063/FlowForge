// DnsConfig.cpp
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <ws2tcpip.h>   // InetPtonW
#include <string>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")

#include "DNS.hpp"

namespace {

std::wstring g_lastErr;

void SetErr(const std::wstring& s) { g_lastErr = s; }

bool IsIPv4(const std::wstring& s) {
    IN_ADDR a{};
    return InetPtonW(AF_INET, s.c_str(), &a) == 1;
}
bool IsIPv6(const std::wstring& s) {
    IN6_ADDR a6{};
    return InetPtonW(AF_INET6, s.c_str(), &a6) == 1;
}

bool LuidToName(const NET_LUID& luid, std::wstring& outName) {
    wchar_t buf[IF_MAX_STRING_SIZE + 1]{};
    if (ConvertInterfaceLuidToNameW(&luid, buf, IF_MAX_STRING_SIZE) != NO_ERROR) {
        SetErr(L"ConvertInterfaceLuidToNameW failed");
        return false;
    }
    outName.assign(buf);
    return !outName.empty();
}

bool RunNetsh(const std::wstring& args, DWORD* exitCode = nullptr) {
    // Собираем командную строку: "netsh.exe " + args
    std::wstring cmd = L"\"netsh.exe\" " + args;

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    // Без окна
    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        DWORD le = GetLastError();
        SetErr(L"CreateProcessW(netsh) failed, Win32=" + std::to_wstring(le));
        return false;
    }
    CloseHandle(pi.hThread);

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);

    if (exitCode) *exitCode = code;
    if (code != 0) {
        SetErr(L"netsh exit code = " + std::to_wstring(code) + L" for: " + args);
        return false;
    }
    return true;
}

bool SetIPv4(const std::wstring& ifName, const std::vector<std::wstring>& v4) {
    if (v4.empty()) return true;

    // Primary
    std::wstring args = L"interface ipv4 set dnsservers name=\"" + ifName +
                        L"\" static " + v4[0] + L" primary validate=no";
    if (!RunNetsh(args)) return false;

    // Secondary/other
    for (size_t i = 1; i < v4.size(); ++i) {
        std::wstring add = L"interface ipv4 add dnsservers name=\"" + ifName +
                           L"\" " + v4[i] + L" index=" + std::to_wstring(i + 1) + L" validate=no";
        if (!RunNetsh(add)) return false;
    }
    return true;
}

bool SetIPv6(const std::wstring& ifName, const std::vector<std::wstring>& v6) {
    if (v6.empty()) return true;

    // На всякий случай очистим все существующие (не везде нужен DHCP для v6)
    (void)RunNetsh(L"interface ipv6 delete dnsservers name=\"" + ifName + L"\" all");

    for (size_t i = 0; i < v6.size(); ++i) {
        std::wstring add = L"interface ipv6 add dnsservers name=\"" + ifName +
                           L"\" address=" + v6[i] + L" index=" + std::to_wstring(i + 1);
        if (!RunNetsh(add)) return false;
    }
    return true;
}

bool UnsetIPv4(const std::wstring& ifName) {
    // Возврат к DHCP (если интерфейс его поддерживает)
    if (RunNetsh(L"interface ipv4 set dnsservers name=\"" + ifName + L"\" dhcp"))
        return true;

    // Если dhcp не сработал — просто удалим все записи
    return RunNetsh(L"interface ipv4 delete dnsservers name=\"" + ifName + L"\" all");
}

bool UnsetIPv6(const std::wstring& ifName) {
    // Для IPv6 чаще достаточно удалить все записи:
    return RunNetsh(L"interface ipv6 delete dnsservers name=\"" + ifName + L"\" all");
}

} // namespace

namespace dns {

bool Dns_Set(NET_LUID luid,
             const std::vector<std::wstring>& servers,
             const std::wstring& /*suffix*/) noexcept
{
    g_lastErr.clear();
    if (servers.empty()) { SetErr(L"servers is empty"); return false; }

    std::wstring ifName;
    if (!LuidToName(luid, ifName)) return false;

    std::vector<std::wstring> v4, v6;
    v4.reserve(servers.size());
    v6.reserve(servers.size());
    for (const auto& s : servers) {
        if (IsIPv4(s)) v4.push_back(s);
        else if (IsIPv6(s)) v6.push_back(s);
        else {
            SetErr(L"Invalid IP address: " + s);
            return false;
        }
    }

    if (!SetIPv4(ifName, v4)) return false;
    if (!SetIPv6(ifName, v6)) return false;

    // NOTE: per-interface DNS suffix не настраиваем здесь (см. комментарий выше).
    return true;
}

bool Dns_Unset(NET_LUID luid) noexcept {
    g_lastErr.clear();

    std::wstring ifName;
    if (!LuidToName(luid, ifName)) return false;

    bool ok4 = UnsetIPv4(ifName);
    bool ok6 = UnsetIPv6(ifName);
    return ok4 && ok6;
}

std::wstring Dns_LastError() { return g_lastErr; }

} // namespace dns
