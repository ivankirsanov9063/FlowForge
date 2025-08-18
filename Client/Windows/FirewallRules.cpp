// fw_rules.cpp — Windows-only, VPN client firewall helper
// Теперь создаёт ДВА правила: UDP и TCP на <server_ip>:<port> для вашего .exe.
// Также умеет удалять правила по префиксу.
//
// Build (MSVC):
//   cl /std:c++20 /EHsc fw_rules.cpp ole32.lib oleaut32.lib
//
// CMake:
//   target_link_libraries(your_target PRIVATE ole32 oleaut32)
//
// Требуются: <netfw.h> и ATL (CComPtr/CComBSTR).
#include "FirewallRules.hpp"

#include <windows.h>
#include <netfw.h>
#include <atlbase.h>
#include <atlcomcli.h>
#include <string>
#include <cstdint>
#include <vector>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace { // ===== internal helpers =====

struct ComInit {
    HRESULT hr = S_OK;
    ComInit() { hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED); }
    ~ComInit(){ if (SUCCEEDED(hr)) CoUninitialize(); }
    bool ok() const { return SUCCEEDED(hr); }
};

std::wstring g_lastError;

static void SetLastErrorHr(HRESULT hr, const wchar_t* where) {
    wchar_t* msgBuf = nullptr;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD len = FormatMessageW(flags, nullptr, hr, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                               (LPWSTR)&msgBuf, 0, nullptr);
    std::wstring msg = (len && msgBuf) ? std::wstring(msgBuf, msgBuf + len) : L"";
    if (msgBuf) LocalFree(msgBuf);

    wchar_t hex[11]{};
    swprintf(hex, 11, L"%08X", (unsigned)hr);
    g_lastError = L"[" + std::wstring(where) + L"] HRESULT=0x" + hex + (msg.empty()? L"" : (L" : " + msg));
}

static bool GetPolicy(INetFwPolicy2** outPolicy) {
    *outPolicy = nullptr;
    CComPtr<INetFwPolicy2> policy;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
                                  __uuidof(INetFwPolicy2), (void**)&policy);
    if (FAILED(hr)) { SetLastErrorHr(hr, L"CoCreateInstance(NetFwPolicy2)"); return false; }
    *outPolicy = policy.Detach();
    return true;
}

static bool GetRules(INetFwRules** outRules) {
    *outRules = nullptr;
    CComPtr<INetFwPolicy2> policy;
    if (!GetPolicy(&policy)) return false;
    HRESULT hr = policy->get_Rules(outRules);
    if (FAILED(hr)) { SetLastErrorHr(hr, L"INetFwPolicy2::get_Rules"); return false; }
    return true;
}

static std::wstring MakeClientRuleName(const fw::ClientRule& c, bool isTcp) {
    return c.rule_prefix + (isTcp ? L" Out TCP to " : L" Out UDP to ")
         + c.server_ip + L":" + std::to_wstring(c.udp_port);
}

static bool UpsertRule(INetFwRule* rule) {
    CComPtr<INetFwRules> rules;
    if (!GetRules(&rules)) return false;

    CComBSTR name;
    HRESULT hr = rule->get_Name(&name);
    if (FAILED(hr) || !name || SysStringLen(name) == 0) {
        SetLastErrorHr(FAILED(hr) ? hr : E_INVALIDARG, L"INetFwRule::get_Name");
        return false;
    }

    // remove-then-add (идемпотентно)
    CComPtr<INetFwRule> existing;
    if (SUCCEEDED(rules->Item(name, &existing)) && existing) {
        rules->Remove(name);
    }

    hr = rules->Add(rule);
    if (FAILED(hr)) { SetLastErrorHr(hr, L"INetFwRules::Add"); return false; }
    return true;
}

static bool CreateOutboundRule(const fw::ClientRule& c,
                               long ipProto,         // NET_FW_IP_PROTOCOL_TCP/UDP
                               const wchar_t* nameSuffix, // L"UDP"/L"TCP"
                               const wchar_t* desc) {
    CComPtr<INetFwRule> r;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER,
                                  __uuidof(INetFwRule), (void**)&r);
    if (FAILED(hr)) { SetLastErrorHr(hr, L"CoCreateInstance(NetFwRule)"); return false; }

    const bool isTcp = (ipProto == NET_FW_IP_PROTOCOL_TCP);
    const std::wstring nm = MakeClientRuleName(c, isTcp);

    r->put_Name(CComBSTR(nm.c_str()));
    r->put_Description(CComBSTR(desc));
    r->put_Direction(NET_FW_RULE_DIR_OUT);
    r->put_Action(NET_FW_ACTION_ALLOW);
    r->put_Enabled(VARIANT_TRUE);
    r->put_Profiles(NET_FW_PROFILE2_ALL);
    r->put_InterfaceTypes(CComBSTR(L"All"));

    r->put_Protocol(ipProto);
    r->put_RemoteAddresses(CComBSTR(c.server_ip.c_str()));
    r->put_RemotePorts(CComBSTR(std::to_wstring(c.udp_port).c_str())); // используем тот же порт и для TCP
    r->put_ApplicationName(CComBSTR(c.app_path.c_str()));

    return UpsertRule(r);
}

} // anonymous namespace

namespace fw { // ===== public API =====

bool EnsureClientOutboundUdp(const ClientRule& c) {
    g_lastError.clear();
    ComInit ci;
    if (!ci.ok()) { SetLastErrorHr(ci.hr, L"CoInitializeEx"); return false; }

    // Валидация
    if (c.rule_prefix.empty() || c.app_path.empty() || c.server_ip.empty() || c.udp_port == 0) {
        g_lastError = L"Invalid ClientRule arguments";
        return false;
    }

    // 1) UDP правило
    if (!CreateOutboundRule(c,
            NET_FW_IP_PROTOCOL_UDP,
            L"UDP",
            L"VPN client outbound UDP allow")) {
        return false;
    }

    // 2) TCP правило — тот же dst ip/port
    if (!CreateOutboundRule(c,
            NET_FW_IP_PROTOCOL_TCP,
            L"TCP",
            L"VPN client outbound TCP allow")) {
        // попытка отката UDP-правила (чтобы не оставлять половинку)
        CComPtr<INetFwRules> rules;
        if (GetRules(&rules)) {
            const std::wstring nameUdp = MakeClientRuleName(c, /*isTcp=*/false);
            rules->Remove(CComBSTR(nameUdp.c_str()));
        }
        return false;
    }

    return true;
}

bool RemoveByPrefix(const std::wstring& prefix) {
    g_lastError.clear();
    ComInit ci;
    if (!ci.ok()) { SetLastErrorHr(ci.hr, L"CoInitializeEx"); return false; }

    CComPtr<INetFwRules> rules;
    if (!GetRules(&rules)) return false;

    // Собираем имена для удаления (нельзя удалять во время перечисления)
    std::vector<CComBSTR> toRemove;

    CComPtr<IUnknown> unk;
    HRESULT hr = rules->get__NewEnum(&unk);
    if (FAILED(hr) || !unk) { SetLastErrorHr(hr, L"INetFwRules::get__NewEnum"); return false; }

    CComPtr<IEnumVARIANT> en;
    hr = unk->QueryInterface(__uuidof(IEnumVARIANT), (void**)&en);
    if (FAILED(hr) || !en) { SetLastErrorHr(hr, L"QueryInterface(IEnumVARIANT)"); return false; }

    VARIANT v; VariantInit(&v);
    while (en->Next(1, &v, nullptr) == S_OK) {
        if (v.vt == VT_DISPATCH && v.pdispVal) {
            CComPtr<INetFwRule> rule;
            if (SUCCEEDED(v.pdispVal->QueryInterface(__uuidof(INetFwRule), (void**)&rule)) && rule) {
                CComBSTR name;
                if (SUCCEEDED(rule->get_Name(&name)) && name) {
                    std::wstring n(static_cast<const wchar_t*>(name), SysStringLen(name));
                    if (!prefix.empty() && n.rfind(prefix, 0) == 0) {
                        toRemove.emplace_back(name);
                    }
                }
            }
        }
        VariantClear(&v);
    }

    for (auto& n : toRemove) {
        rules->Remove(n);
    }
    return true;
}

std::wstring LastError() { return g_lastError; }

} // namespace fw
