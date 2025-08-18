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

#include <cstdint>
#include <string>
#include <vector>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace
{

struct ComInit
{
    HRESULT hr = S_OK;

    ComInit()
    {
        hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    }

    ~ComInit()
    {
        if (SUCCEEDED(hr))
        {
            CoUninitialize();
        }
    }

    bool ok() const
    {
        return SUCCEEDED(hr);
    }
};

std::wstring g_last_error;

static void set_last_error_hr(HRESULT hr,
                              const wchar_t *where)
{
    wchar_t *msg_buf = nullptr;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
                  FORMAT_MESSAGE_FROM_SYSTEM |
                  FORMAT_MESSAGE_IGNORE_INSERTS;

    DWORD len = FormatMessageW(flags,
                               nullptr,
                               hr,
                               MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                               (LPWSTR)&msg_buf,
                               0,
                               nullptr);

    std::wstring msg = (len && msg_buf) ? std::wstring(msg_buf, msg_buf + len) : L"";
    if (msg_buf)
    {
        LocalFree(msg_buf);
    }

    wchar_t hex[11]{};
    swprintf(hex, 11, L"%08X", static_cast<unsigned>(hr));
    g_last_error = L"["
                 + std::wstring(where)
                 + L"] HRESULT=0x"
                 + hex
                 + (msg.empty() ? L"" : (L" : " + msg));
}

static bool get_policy(INetFwPolicy2 **out_policy)
{
    *out_policy = nullptr;

    CComPtr<INetFwPolicy2> policy;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2),
                                  nullptr,
                                  CLSCTX_INPROC_SERVER,
                                  __uuidof(INetFwPolicy2),
                                  (void **)&policy);
    if (FAILED(hr))
    {
        set_last_error_hr(hr, L"CoCreateInstance(NetFwPolicy2)");
        return false;
    }

    *out_policy = policy.Detach();
    return true;
}

static bool get_rules(INetFwRules **out_rules)
{
    *out_rules = nullptr;

    CComPtr<INetFwPolicy2> policy;
    if (!get_policy(&policy))
    {
        return false;
    }

    HRESULT hr = policy->get_Rules(out_rules);
    if (FAILED(hr))
    {
        set_last_error_hr(hr, L"INetFwPolicy2::get_Rules");
        return false;
    }
    return true;
}

static std::wstring make_client_rule_name(const FirewallRules::ClientRule &c,
                                          bool is_tcp)
{
    return c.rule_prefix + (is_tcp ? L" Out TCP to " : L" Out UDP to ")
         + c.server_ip + L":" + std::to_wstring(c.udp_port);
}

static bool upsert_rule(INetFwRule *rule)
{
    CComPtr<INetFwRules> rules;
    if (!get_rules(&rules))
    {
        return false;
    }

    CComBSTR name;
    HRESULT hr = rule->get_Name(&name);
    if (FAILED(hr) || !name || SysStringLen(name) == 0)
    {
        set_last_error_hr(FAILED(hr) ? hr : E_INVALIDARG, L"INetFwRule::get_Name");
        return false;
    }

    // remove-then-add (идемпотентно)
    CComPtr<INetFwRule> existing;
    if (SUCCEEDED(rules->Item(name, &existing)) && existing)
    {
        rules->Remove(name);
    }

    hr = rules->Add(rule);
    if (FAILED(hr))
    {
        set_last_error_hr(hr, L"INetFwRules::Add");
        return false;
    }
    return true;
}

static bool create_outbound_rule(const FirewallRules::ClientRule &c,
                                 long ip_proto,                // NET_FW_IP_PROTOCOL_TCP/UDP
                                 const wchar_t *name_suffix,   // L"UDP"/L"TCP"
                                 const wchar_t *desc)
{
    (void)name_suffix;

    CComPtr<INetFwRule> r;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwRule),
                                  nullptr,
                                  CLSCTX_INPROC_SERVER,
                                  __uuidof(INetFwRule),
                                  (void **)&r);
    if (FAILED(hr))
    {
        set_last_error_hr(hr, L"CoCreateInstance(NetFwRule)");
        return false;
    }

    const bool is_tcp = (ip_proto == NET_FW_IP_PROTOCOL_TCP);
    const std::wstring nm = make_client_rule_name(c, is_tcp);

    r->put_Name(CComBSTR(nm.c_str()));
    r->put_Description(CComBSTR(desc));
    r->put_Direction(NET_FW_RULE_DIR_OUT);
    r->put_Action(NET_FW_ACTION_ALLOW);
    r->put_Enabled(VARIANT_TRUE);
    r->put_Profiles(NET_FW_PROFILE2_ALL);
    r->put_InterfaceTypes(CComBSTR(L"All"));

    r->put_Protocol(ip_proto);
    r->put_RemoteAddresses(CComBSTR(c.server_ip.c_str()));
    r->put_RemotePorts(CComBSTR(std::to_wstring(c.udp_port).c_str())); // используем тот же порт и для TCP
    r->put_ApplicationName(CComBSTR(c.app_path.c_str()));

    return upsert_rule(r);
}

} // anonymous namespace

namespace FirewallRules
{

bool EnsureClientOutboundUdp(const ClientRule &c)
{
    g_last_error.clear();

    ComInit ci;
    if (!ci.ok())
    {
        set_last_error_hr(ci.hr, L"CoInitializeEx");
        return false;
    }

    // Валидация
    if (c.rule_prefix.empty() || c.app_path.empty() || c.server_ip.empty() || c.udp_port == 0)
    {
        g_last_error = L"Invalid ClientRule arguments";
        return false;
    }

    // 1) UDP правило
    if (!create_outbound_rule(c,
                              NET_FW_IP_PROTOCOL_UDP,
                              L"UDP",
                              L"VPN client outbound UDP allow"))
    {
        return false;
    }

    // 2) TCP правило — тот же dst ip/port
    if (!create_outbound_rule(c,
                              NET_FW_IP_PROTOCOL_TCP,
                              L"TCP",
                              L"VPN client outbound TCP allow"))
    {
        // попытка отката UDP-правила (чтобы не оставлять половинку)
        CComPtr<INetFwRules> rules;
        if (get_rules(&rules))
        {
            const std::wstring name_udp = make_client_rule_name(c, /*is_tcp=*/false);
            rules->Remove(CComBSTR(name_udp.c_str()));
        }
        return false;
    }

    return true;
}

bool RemoveByPrefix(const std::wstring &prefix)
{
    g_last_error.clear();

    ComInit ci;
    if (!ci.ok())
    {
        set_last_error_hr(ci.hr, L"CoInitializeEx");
        return false;
    }

    CComPtr<INetFwRules> rules;
    if (!get_rules(&rules))
    {
        return false;
    }

    // Собираем имена для удаления (нельзя удалять во время перечисления)
    std::vector<CComBSTR> to_remove;

    CComPtr<IUnknown> unk;
    HRESULT hr = rules->get__NewEnum(&unk);
    if (FAILED(hr) || !unk)
    {
        set_last_error_hr(hr, L"INetFwRules::get__NewEnum");
        return false;
    }

    CComPtr<IEnumVARIANT> en;
    hr = unk->QueryInterface(__uuidof(IEnumVARIANT), (void **)&en);
    if (FAILED(hr) || !en)
    {
        set_last_error_hr(hr, L"QueryInterface(IEnumVARIANT)");
        return false;
    }

    VARIANT v;
    VariantInit(&v);
    while (en->Next(1, &v, nullptr) == S_OK)
    {
        if (v.vt == VT_DISPATCH && v.pdispVal)
        {
            CComPtr<INetFwRule> rule;
            if (SUCCEEDED(v.pdispVal->QueryInterface(__uuidof(INetFwRule), (void **)&rule)) && rule)
            {
                CComBSTR name;
                if (SUCCEEDED(rule->get_Name(&name)) && name)
                {
                    std::wstring n(static_cast<const wchar_t *>(name), SysStringLen(name));
                    if (!prefix.empty() && n.rfind(prefix, 0) == 0)
                    {
                        to_remove.emplace_back(name);
                    }
                }
            }
        }
        VariantClear(&v);
    }

    for (auto &n : to_remove)
    {
        rules->Remove(n);
    }
    return true;
}

std::wstring LastError()
{
    return g_last_error;
}

} // namespace FirewallRules
