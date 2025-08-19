// FirewallRules.cpp — RAII для правил Windows Firewall (VPN-клиент)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
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
#include "Logger.hpp"

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

static std::string ToUtf8(const std::wstring &ws)
{
    if (ws.empty())
    {
        return std::string();
    }
    int need = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(),
                                   static_cast<int>(ws.size()),
                                   nullptr, 0, nullptr, nullptr);
    if (need <= 0)
    {
        return std::string();
    }
    std::string out;
    out.resize(need);
    (void)WideCharToMultiByte(CP_UTF8, 0, ws.c_str(),
                              static_cast<int>(ws.size()),
                              out.data(), need, nullptr, nullptr);
    return out;
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

    LOGE("firewallrules") << "HrErr at " << where_utf8 << " hr=0x" << std::hex
                          << static_cast<unsigned>(hr) << std::dec;
    return std::runtime_error(std::string(wmsg.begin(), wmsg.end()));
}

static CComPtr<INetFwPolicy2> GetPolicy2()
{
    LOGD("firewallrules") << "GetPolicy2: CoCreateInstance(NetFwPolicy2)";
    CComPtr<INetFwPolicy2> p;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
                                  __uuidof(INetFwPolicy2), reinterpret_cast<void **>(&p));
    if (FAILED(hr) || !p)
    {
        LOGE("firewallrules") << "GetPolicy2 failed hr=0x" << std::hex << static_cast<unsigned>(hr) << std::dec;
        throw HrErr("CoCreateInstance(NetFwPolicy2)", FAILED(hr) ? hr : E_POINTER);
    }
    LOGT("firewallrules") << "GetPolicy2: success";
    return p;
}

static CComPtr<INetFwRules> GetRules()
{
    LOGD("firewallrules") << "GetRules: INetFwPolicy2::get_Rules";
    CComPtr<INetFwPolicy2> pol = GetPolicy2();
    CComPtr<INetFwRules> rules;
    HRESULT hr = pol->get_Rules(&rules);
    if (FAILED(hr) || !rules)
    {
        LOGE("firewallrules") << "get_Rules failed hr=0x" << std::hex << static_cast<unsigned>(hr) << std::dec;
        throw HrErr("INetFwPolicy2::get_Rules", FAILED(hr) ? hr : E_POINTER);
    }
    LOGT("firewallrules") << "GetRules: success";
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
        LOGE("firewallrules") << "CoInitializeEx failed hr=0x" << std::hex
                              << static_cast<unsigned>(hr_) << std::dec;
        throw HrErr("CoInitializeEx", static_cast<HRESULT>(hr_));
    }
    LOGD("firewallrules") << "COM initialized (STA)";
}

FirewallRules::ComInit::~ComInit()
{
    if (SUCCEEDED(static_cast<HRESULT>(hr_)))
    {
        CoUninitialize();
        LOGT("firewallrules") << "COM uninitialized";
    }
}

// --------- FirewallRules ---------

FirewallRules::FirewallRules(const ClientRule &cfg) noexcept
    : cfg_(cfg)
{
    LOGD("firewallrules") << "FirewallRules: constructed"
                          << " prefix=" << ToUtf8(cfg_.rule_prefix)
                          << " app=" << ToUtf8(cfg_.app_path)
                          << " server=" << ToUtf8(cfg_.server_ip);
}

FirewallRules::~FirewallRules()
{
    try
    {
        LOGD("firewallrules") << "FirewallRules: destructor -> Revert()";
        Revert();
        LOGD("firewallrules") << "FirewallRules: revert completed";
    }
    catch (...)
    {
        // no-throw
        LOGW("firewallrules") << "FirewallRules: exception swallowed in destructor during Revert()";
    }
}

FirewallRules::FirewallRules(FirewallRules &&other) noexcept
{
    LOGT("firewallrules") << "FirewallRules: move-ctor";
    *this = std::move(other);
}

FirewallRules &FirewallRules::operator=(FirewallRules &&other) noexcept
{
    if (this != &other)
    {
        LOGT("firewallrules") << "FirewallRules: move-assign";
        try { Revert(); } catch (...) { LOGW("firewallrules") << "move-assign: Revert swallowed exception"; }

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
    if (cfg_.rule_prefix.empty())
    {
        LOGE("firewallrules") << "ValidateConfig: rule_prefix is empty";
        throw std::invalid_argument("FirewallRules: rule_prefix is empty");
    }
    if (cfg_.app_path.empty())
    {
        LOGE("firewallrules") << "ValidateConfig: app_path is empty";
        throw std::invalid_argument("FirewallRules: app_path is empty");
    }
    if (cfg_.server_ip.empty())
    {
        LOGE("firewallrules") << "ValidateConfig: server_ip is empty";
        throw std::invalid_argument("FirewallRules: server_ip is empty");
    }
    LOGT("firewallrules") << "ValidateConfig: ok";
}

std::wstring FirewallRules::MakeRuleName(Protocol proto, std::uint16_t port) const
{
    const bool is_tcp = (proto == Protocol::TCP);
    std::wstring name = cfg_.rule_prefix
                      + (is_tcp ? L" Out TCP to " : L" Out UDP to ")
                      + cfg_.server_ip + L":" + std::to_wstring(port);
    LOGT("firewallrules") << "MakeRuleName: " << ToUtf8(name);
    return name;
}

void FirewallRules::ReadSnapshot(const std::wstring &name, RuleSnapshot &out) const
{
    LOGD("firewallrules") << "ReadSnapshot: name=" << ToUtf8(name);
    out = {};

    CComPtr<INetFwRules> rules = GetRules();

    CComPtr<INetFwRule> r;
    HRESULT hr = rules->Item(B(name), &r);
    if (FAILED(hr) || !r)
    {
        out.present = false;
        LOGT("firewallrules") << "ReadSnapshot: not present";
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
    LOGD("firewallrules") << "ReadSnapshot: present, name=" << ToUtf8(out.name);
}

void FirewallRules::RemoveIfExists(const std::wstring &name) const
{
    CComPtr<INetFwRules> rules = GetRules();

    CComPtr<INetFwRule> existing;
    if (SUCCEEDED(rules->Item(B(name), &existing)) && existing)
    {
        LOGD("firewallrules") << "RemoveIfExists: " << ToUtf8(name);
        (void)rules->Remove(B(name));
    }
    else
    {
        LOGT("firewallrules") << "RemoveIfExists: nothing to remove for " << ToUtf8(name);
    }
}

void FirewallRules::UpsertOutbound(Protocol proto, std::uint16_t port, const std::wstring &name) const
{
    LOGD("firewallrules") << "UpsertOutbound: proto=" << (proto == Protocol::TCP ? "TCP" : "UDP")
                          << " port=" << port << " name=" << ToUtf8(name);
    CComPtr<INetFwRules> rules = GetRules();

    CComPtr<INetFwRule> r;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER,
                                  __uuidof(INetFwRule), reinterpret_cast<void **>(&r));
    if (FAILED(hr) || !r)
    {
        LOGE("firewallrules") << "CoCreateInstance(NetFwRule) failed hr=0x"
                              << std::hex << static_cast<unsigned>(hr) << std::dec;
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
        LOGE("firewallrules") << "INetFwRules::Add failed hr=0x"
                              << std::hex << static_cast<unsigned>(hr) << std::dec;
        throw HrErr("INetFwRules::Add", hr);
    }
    LOGI("firewallrules") << "UpsertOutbound: rule added";
}

void FirewallRules::RestoreFromSnapshot(const RuleSnapshot &s) const
{
    if (!s.present)
    {
        LOGT("firewallrules") << "RestoreFromSnapshot: nothing to restore";
        return;
    }

    LOGD("firewallrules") << "RestoreFromSnapshot: " << ToUtf8(s.name);
    CComPtr<INetFwRules> rules = GetRules();

    CComPtr<INetFwRule> r;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER,
                                  __uuidof(INetFwRule), reinterpret_cast<void **>(&r));
    if (FAILED(hr) || !r)
    {
        LOGE("firewallrules") << "CoCreateInstance(NetFwRule) failed hr=0x"
                              << std::hex << static_cast<unsigned>(hr) << std::dec;
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
        LOGE("firewallrules") << "INetFwRules::Add(restore) failed hr=0x"
                              << std::hex << static_cast<unsigned>(hr) << std::dec;
        throw HrErr("INetFwRules::Add (restore)", hr);
    }
    LOGI("firewallrules") << "RestoreFromSnapshot: rule restored";
}

void FirewallRules::RemoveAllWithPrefix(const std::wstring &prefix)
{
    LOGD("firewallrules") << "RemoveAllWithPrefix: prefix=" << ToUtf8(prefix);
    CComPtr<INetFwRules> rules = GetRules();

    std::vector<CComBSTR> to_remove;

    CComPtr<IUnknown> unk;
    HRESULT hr = rules->get__NewEnum(&unk);
    if (FAILED(hr) || !unk)
    {
        LOGE("firewallrules") << "get__NewEnum failed hr=0x" << std::hex
                              << static_cast<unsigned>(hr) << std::dec;
        throw HrErr("INetFwRules::get__NewEnum", FAILED(hr) ? hr : E_POINTER);
    }

    CComPtr<IEnumVARIANT> en;
    hr = unk->QueryInterface(__uuidof(IEnumVARIANT), reinterpret_cast<void **>(&en));
    if (FAILED(hr) || !en)
    {
        LOGE("firewallrules") << "QueryInterface(IEnumVARIANT) failed hr=0x" << std::hex
                              << static_cast<unsigned>(hr) << std::dec;
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
                                                     reinterpret_cast<void **>(&rule)) ) && rule)
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
        LOGD("firewallrules") << "Remove: " << ToUtf8(std::wstring(n, n.Length()));
        (void)rules->Remove(n);
    }
    LOGI("firewallrules") << "RemoveAllWithPrefix: removed=" << to_remove.size();
}

// --------- public API ---------

void FirewallRules::Allow(Protocol proto, std::uint16_t port)
{
    LOGI("firewallrules") << "Allow: proto=" << (proto == Protocol::TCP ? "TCP" : "UDP")
                          << " port=" << port;
    ValidateConfig();
    if (port == 0)
    {
        LOGE("firewallrules") << "Allow: port is zero";
        throw std::invalid_argument("FirewallRules::Allow: port is zero");
    }

    // Уже добавляли такой же? — делаем идемпотентно.
    for (const auto &e : entries_)
    {
        if (e.proto == proto && e.port == port)
        {
            LOGT("firewallrules") << "Allow: already present (idempotent)";
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
        LOGE("firewallrules") << "Allow: UpsertOutbound threw";
        // ничего не записали — выходим с ошибкой
        throw;
    }

    entries_.push_back(std::move(entry));
    applied_ = true;
    LOGI("firewallrules") << "Allow: rule applied";
}

void FirewallRules::Revert()
{
    if (!applied_)
    {
        LOGT("firewallrules") << "Revert: nothing to do";
        return;
    }

    ComInit com; // STA
    bool err = false;

    LOGI("firewallrules") << "Revert: begin, entries=" << entries_.size();

    // Откатываем в обратном порядке добавления
    for (auto it = entries_.rbegin(); it != entries_.rend(); ++it)
    {
        try
        {
            if (it->touched)
            {
                LOGD("firewallrules") << "Revert: remove " << ToUtf8(it->name);
                RemoveIfExists(it->name);
            }
        }
        catch (...)
        {
            LOGE("firewallrules") << "Revert: remove failed";
            err = true;
        }

        try
        {
            if (it->had_before)
            {
                LOGD("firewallrules") << "Revert: restore " << ToUtf8(it->snapshot.name);
                RestoreFromSnapshot(it->snapshot);
            }
        }
        catch (...)
        {
            LOGE("firewallrules") << "Revert: restore failed";
            err = true;
        }
    }

    entries_.clear();
    applied_ = false;

    if (err)
    {
        LOGE("firewallrules") << "Revert: one or more operations failed";
        throw std::runtime_error("FirewallRules::Revert: one or more operations failed");
    }
    LOGI("firewallrules") << "Revert: done";
}

void FirewallRules::RemoveByPrefix(const std::wstring &prefix)
{
    if (prefix.empty())
    {
        LOGE("firewallrules") << "RemoveByPrefix: empty prefix";
        throw std::invalid_argument("FirewallRules::RemoveByPrefix: empty prefix");
    }
    ComInit com; // STA
    LOGI("firewallrules") << "RemoveByPrefix: " << ToUtf8(prefix);
    RemoveAllWithPrefix(prefix);
}
