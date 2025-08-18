// FirewallRules.cpp — RAII для правил Windows Firewall (VPN-клиент)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>
#include <netfw.h>
#include <atlbase.h>
#include <atlcomcli.h>

#include <string>
#include <vector>
#include <stdexcept>
#include <utility>

#include "FirewallRules.hpp"

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace
{

static std::wstring ToHex8(unsigned x)
{
    wchar_t buf[11]{};
    swprintf(buf, 11, L"%08X", x);
    return buf;
}

static std::runtime_error HrErr(const char *where_utf8, HRESULT hr)
{
    // Формируем wide-строку из UTF-8 места ошибки
    int need = MultiByteToWideChar(CP_UTF8, 0, where_utf8, -1, nullptr, 0);
    std::wstring where;
    where.resize(need > 0 ? need - 1 : 0);
    if (need > 1) { MultiByteToWideChar(CP_UTF8, 0, where_utf8, -1, where.data(), need); }

    std::wstring wmsg = L"[";
    wmsg += where;
    wmsg += L"] HRESULT=0x";
    wmsg += ToHex8(static_cast<unsigned>(hr));

    return std::runtime_error(std::string(wmsg.begin(), wmsg.end()));
}

static CComPtr<INetFwPolicy2> GetPolicy2()
{
    CComPtr<INetFwPolicy2> p;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
                                  __uuidof(INetFwPolicy2), reinterpret_cast<void **>(&p));
    if (FAILED(hr) || !p)
    {
        throw HrErr("CoCreateInstance(NetFwPolicy2)", FAILED(hr) ? hr : E_POINTER);
    }
    return p;
}

static CComPtr<INetFwRules> GetRules()
{
    CComPtr<INetFwPolicy2> pol = GetPolicy2();
    CComPtr<INetFwRules> rules;
    HRESULT hr = pol->get_Rules(&rules);
    if (FAILED(hr) || !rules)
    {
        throw HrErr("INetFwPolicy2::get_Rules", FAILED(hr) ? hr : E_POINTER);
    }
    return rules;
}

static CComBSTR B(const std::wstring &ws)
{
    return CComBSTR(ws.c_str());
}

} // namespace

// --------- ComInit ---------

FirewallRules::ComInit::ComInit()
{
    hr_ = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(static_cast<HRESULT>(hr_)))
    {
        throw HrErr("CoInitializeEx", static_cast<HRESULT>(hr_));
    }
}

FirewallRules::ComInit::~ComInit()
{
    if (SUCCEEDED(static_cast<HRESULT>(hr_)))
    {
        CoUninitialize();
    }
}

// --------- FirewallRules ---------

FirewallRules::FirewallRules(const ClientRule &cfg) noexcept
    : cfg_(cfg)
{
}

FirewallRules::~FirewallRules()
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

FirewallRules::FirewallRules(FirewallRules &&other) noexcept
{
    *this = std::move(other);
}

FirewallRules &FirewallRules::operator=(FirewallRules &&other) noexcept
{
    if (this != &other)
    {
        try { Revert(); } catch (...) {}

        cfg_      = std::move(other.cfg_);
        entries_  = std::move(other.entries_);
        applied_  = other.applied_;

        other.applied_ = false;
        other.entries_.clear();
    }
    return *this;
}

void FirewallRules::ValidateConfig() const
{
    if (cfg_.rule_prefix.empty()) { throw std::invalid_argument("FirewallRules: rule_prefix is empty"); }
    if (cfg_.app_path.empty())    { throw std::invalid_argument("FirewallRules: app_path is empty"); }
    if (cfg_.server_ip.empty())   { throw std::invalid_argument("FirewallRules: server_ip is empty"); }
}

std::wstring FirewallRules::MakeRuleName(Protocol proto, std::uint16_t port) const
{
    const bool is_tcp = (proto == Protocol::TCP);
    return cfg_.rule_prefix
         + (is_tcp ? L" Out TCP to " : L" Out UDP to ")
         + cfg_.server_ip + L":" + std::to_wstring(port);
}

void FirewallRules::ReadSnapshot(const std::wstring &name, RuleSnapshot &out) const
{
    out = {};

    CComPtr<INetFwRules> rules = GetRules();

    CComPtr<INetFwRule> r;
    HRESULT hr = rules->Item(B(name), &r);
    if (FAILED(hr) || !r)
    {
        out.present = false;
        return;
    }

    BSTR b = nullptr;
    long l = 0;
    VARIANT_BOOL vb = VARIANT_FALSE;

    if (SUCCEEDED(r->get_Name(&b)) && b)               { out.name.assign(b, SysStringLen(b)); SysFreeString(b); }
    if (SUCCEEDED(r->get_Description(&b)) && b)        { out.description.assign(b, SysStringLen(b)); SysFreeString(b); }

    // >>> вот эти две строки — через enum
    NET_FW_RULE_DIRECTION dir = NET_FW_RULE_DIR_IN;
    if (SUCCEEDED(r->get_Direction(&dir)))             { out.direction = static_cast<long>(dir); }

    NET_FW_ACTION act = NET_FW_ACTION_BLOCK;
    if (SUCCEEDED(r->get_Action(&act)))                { out.action = static_cast<long>(act); }
    // <<<

    if (SUCCEEDED(r->get_Enabled(&vb)))                { out.enabled = (vb == VARIANT_TRUE); }
    if (SUCCEEDED(r->get_Profiles(&l)))                { out.profiles = l; }
    if (SUCCEEDED(r->get_InterfaceTypes(&b)) && b)     { out.interface_types.assign(b, SysStringLen(b)); SysFreeString(b); }
    if (SUCCEEDED(r->get_Protocol(&l)))                { out.protocol = l; }
    if (SUCCEEDED(r->get_RemoteAddresses(&b)) && b)    { out.remote_addresses.assign(b, SysStringLen(b)); SysFreeString(b); }
    if (SUCCEEDED(r->get_RemotePorts(&b)) && b)        { out.remote_ports.assign(b, SysStringLen(b)); SysFreeString(b); }
    if (SUCCEEDED(r->get_ApplicationName(&b)) && b)    { out.application_name.assign(b, SysStringLen(b)); SysFreeString(b); }

    out.present = true;
}

void FirewallRules::RemoveIfExists(const std::wstring &name) const
{
    CComPtr<INetFwRules> rules = GetRules();

    CComPtr<INetFwRule> existing;
    if (SUCCEEDED(rules->Item(B(name), &existing)) && existing)
    {
        (void)rules->Remove(B(name));
    }
}

void FirewallRules::UpsertOutbound(Protocol proto, std::uint16_t port, const std::wstring &name) const
{
    CComPtr<INetFwRules> rules = GetRules();

    CComPtr<INetFwRule> r;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER,
                                  __uuidof(INetFwRule), reinterpret_cast<void **>(&r));
    if (FAILED(hr) || !r)
    {
        throw HrErr("CoCreateInstance(NetFwRule)", FAILED(hr) ? hr : E_POINTER);
    }

    const long ip_proto = (proto == Protocol::TCP) ? NET_FW_IP_PROTOCOL_TCP : NET_FW_IP_PROTOCOL_UDP;

    r->put_Name(B(name));
    r->put_Description(B(L"VPN client outbound allow"));
    r->put_Direction(NET_FW_RULE_DIR_OUT);
    r->put_Action(NET_FW_ACTION_ALLOW);
    r->put_Enabled(VARIANT_TRUE);
    r->put_Profiles(NET_FW_PROFILE2_ALL);
    r->put_InterfaceTypes(B(L"All"));

    r->put_Protocol(ip_proto);
    r->put_RemoteAddresses(B(cfg_.server_ip));
    r->put_RemotePorts(B(std::to_wstring(port)));
    r->put_ApplicationName(B(cfg_.app_path));

    RemoveIfExists(name); // идемпотентно
    hr = rules->Add(r);
    if (FAILED(hr))
    {
        throw HrErr("INetFwRules::Add", hr);
    }
}

void FirewallRules::RestoreFromSnapshot(const RuleSnapshot &s) const
{
    if (!s.present)
    {
        return;
    }

    CComPtr<INetFwRules> rules = GetRules();

    CComPtr<INetFwRule> r;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER,
                                  __uuidof(INetFwRule), reinterpret_cast<void **>(&r));
    if (FAILED(hr) || !r)
    {
        throw HrErr("CoCreateInstance(NetFwRule)", FAILED(hr) ? hr : E_POINTER);
    }

    r->put_Name(B(s.name));
    r->put_Description(B(s.description));

    // >>> вот эти две — через enum
    r->put_Direction(static_cast<NET_FW_RULE_DIRECTION>(s.direction));
    r->put_Action(static_cast<NET_FW_ACTION>(s.action));
    // <<<

    r->put_Enabled(s.enabled ? VARIANT_TRUE : VARIANT_FALSE);
    r->put_Profiles(s.profiles);
    r->put_InterfaceTypes(B(s.interface_types));
    r->put_Protocol(s.protocol);
    r->put_RemoteAddresses(B(s.remote_addresses));
    r->put_RemotePorts(B(s.remote_ports));
    r->put_ApplicationName(B(s.application_name));

    RemoveIfExists(s.name);
    hr = rules->Add(r);
    if (FAILED(hr))
    {
        throw HrErr("INetFwRules::Add (restore)", hr);
    }
}

void FirewallRules::RemoveAllWithPrefix(const std::wstring &prefix)
{
    CComPtr<INetFwRules> rules = GetRules();

    std::vector<CComBSTR> to_remove;

    CComPtr<IUnknown> unk;
    HRESULT hr = rules->get__NewEnum(&unk);
    if (FAILED(hr) || !unk)
    {
        throw HrErr("INetFwRules::get__NewEnum", FAILED(hr) ? hr : E_POINTER);
    }

    CComPtr<IEnumVARIANT> en;
    hr = unk->QueryInterface(__uuidof(IEnumVARIANT), reinterpret_cast<void **>(&en));
    if (FAILED(hr) || !en)
    {
        throw HrErr("QueryInterface(IEnumVARIANT)", FAILED(hr) ? hr : E_POINTER);
    }

    VARIANT v;
    VariantInit(&v);
    while (en->Next(1, &v, nullptr) == S_OK)
    {
        if (v.vt == VT_DISPATCH && v.pdispVal)
        {
            CComPtr<INetFwRule> rule;
            if (SUCCEEDED(v.pdispVal->QueryInterface(__uuidof(INetFwRule),
                                                     reinterpret_cast<void **>(&rule))) && rule)
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
        (void)rules->Remove(n);
    }
}

// --------- public API ---------

void FirewallRules::Allow(Protocol proto, std::uint16_t port)
{
    ValidateConfig();
    if (port == 0)
    {
        throw std::invalid_argument("FirewallRules::Allow: port is zero");
    }

    // Уже добавляли такой же? — делаем идемпотентно.
    for (const auto &e : entries_)
    {
        if (e.proto == proto && e.port == port)
        {
            return;
        }
    }

    const std::wstring name = MakeRuleName(proto, port);

    ComInit com; // STA

    Entry entry;
    entry.proto = proto;
    entry.port  = port;
    entry.name  = name;

    ReadSnapshot(name, entry.snapshot);
    entry.had_before = entry.snapshot.present;

    try
    {
        UpsertOutbound(proto, port, name);
        entry.touched = true;
    }
    catch (...)
    {
        // ничего не записали — выходим с ошибкой
        throw;
    }

    entries_.push_back(std::move(entry));
    applied_ = true;
}

void FirewallRules::Revert()
{
    if (!applied_)
    {
        return;
    }

    ComInit com; // STA
    bool err = false;

    // Откатываем в обратном порядке добавления
    for (auto it = entries_.rbegin(); it != entries_.rend(); ++it)
    {
        try
        {
            if (it->touched)
            {
                RemoveIfExists(it->name);
            }
        }
        catch (...) { err = true; }

        try
        {
            if (it->had_before)
            {
                RestoreFromSnapshot(it->snapshot);
            }
        }
        catch (...) { err = true; }
    }

    entries_.clear();
    applied_ = false;

    if (err)
    {
        throw std::runtime_error("FirewallRules::Revert: one or more operations failed");
    }
}

void FirewallRules::RemoveByPrefix(const std::wstring &prefix)
{
    if (prefix.empty())
    {
        throw std::invalid_argument("FirewallRules::RemoveByPrefix: empty prefix");
    }
    ComInit com; // STA
    RemoveAllWithPrefix(prefix);
}
