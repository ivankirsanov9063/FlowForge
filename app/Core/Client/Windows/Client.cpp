#include "Core/PluginWrapper.hpp"
#include "Core/TUN.hpp"
#include "Core/Logger.hpp"
#include "Network.hpp"
#include "FirewallRules.hpp"
#include "NetWatcher.hpp"
#include "DNS.hpp"
#include "NetworkRollback.hpp"
#include "Client.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
using ssize_t = SSIZE_T;

#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <set>
#include <vector>
#include <sstream>
#include <thread>
#include <boost/json.hpp>
#include <boost/log/trivial.hpp>

static std::atomic<bool> g_started { false };
static volatile sig_atomic_t g_working = 1;
static std::thread g_thread;

static std::string strip_brackets(std::string s)
{
    if (!s.empty() && s.front() == '[' && s.back() == ']')
    {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

static std::wstring utf8_to_wide(const std::string &s)
{
    if (s.empty())
    {
        LOGT("client") << "utf8_to_wide: empty input";
        return std::wstring();
    }
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring ws(len ? len - 1 : 0, L'\0');
    if (len > 1)
    {
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, ws.data(), len);
    }
    return ws;
}

static void debug_packet_info(const std::uint8_t *data,
                              std::size_t len,
                              const char *direction)
{
    if (len < 20)
    {
        return;
    }

    std::uint8_t version = (data[0] >> 4) & 0x0f;
    if (version == 4)
    {
        std::uint32_t src = (data[12] << 24) | (data[13] << 16) | (data[14] << 8) | data[15];
        std::uint32_t dst = (data[16] << 24) | (data[17] << 16) | (data[18] << 8) | data[19];
        LOGT("tun") << "[" << direction << "] IPv4: "
                    << ((src >> 24) & 0xff) << "."
                    << ((src >> 16) & 0xff) << "."
                    << ((src >> 8) & 0xff)  << "."
                    << (src & 0xff) << " -> "
                    << ((dst >> 24) & 0xff) << "."
                    << ((dst >> 16) & 0xff) << "."
                    << ((dst >> 8) & 0xff)  << "."
                    << (dst & 0xff) << " (len=" << len << ")";
    }
    else if (version == 6)
    {
        LOGT("tun") << "[" << direction << "] IPv6 packet (len=" << len << ")";
    }
    else
    {
        LOGW("tun") << "[" << direction << "] Unknown packet version=" << static_cast<int>(version)
                    << " (len=" << len << ")";
    }
}

bool IsElevated() noexcept
{
    HANDLE h_token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &h_token))
    {
        LOGW("client") << "OpenProcessToken failed; assuming not elevated";
        return false;
    }

    TOKEN_ELEVATION elev{};
    DWORD cb = 0;
    const BOOL ok = GetTokenInformation(h_token, TokenElevation, &elev, sizeof(elev), &cb);
    CloseHandle(h_token);
    return ok && elev.TokenIsElevated;
}

/**
 * @brief Возвращает полный путь к текущему исполняемому файлу (.exe).
 * @throw std::runtime_error при ошибке WinAPI.
 */
static std::wstring GetModuleFullPathW()
{
    LOGD("client") << "Querying module path";
    std::wstring path(MAX_PATH, L'\0');
    DWORD n = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (n == 0)
    {
        LOGE("client") << "GetModuleFileNameW failed";
        throw std::runtime_error("GetModuleFileNameW failed");
    }
    if (n >= path.size())
    {
        std::wstring big(4096, L'\0');
        n = GetModuleFileNameW(nullptr, big.data(), static_cast<DWORD>(big.size()));
        if (n == 0 || n >= big.size())
        {
            LOGE("client") << "GetModuleFileNameW failed (long path)";
            throw std::runtime_error("GetModuleFileNameW failed (long path)");
        }
        big.resize(n);
        LOGD("client") << "Module path resolved (len=" << big.size() << ")";
        return big;
    }
    path.resize(n);
    LOGD("client") << "Module path resolved (len=" << path.size() << ")";
    return path;
}

/**
 * @brief Резолвит хост/адрес в список IPv4/IPv6 адресов для поля Firewall RemoteAddresses.
 *        Возвращает CSV-строку адресов без пробелов (поддерживает IPv6).
 *        Если резолв не удался — возвращает исходную строку (без скобок).
 */
static std::wstring ResolveFirewallAddressesW(const std::string &host)
{
    LOGD("firewallrules") << "Resolving server addresses for: " << host;
    std::string h = strip_brackets(host);
    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo *res = nullptr;
    if (getaddrinfo(h.c_str(), nullptr, &hints, &res) != 0)
    {
        LOGW("firewallrules") << "getaddrinfo failed; using literal: " << h;
        return utf8_to_wide(h);
    }
    std::set<std::wstring> uniq;
    wchar_t buf4[INET_ADDRSTRLEN]{};
    wchar_t buf6[INET6_ADDRSTRLEN]{};
    for (addrinfo *ai = res; ai; ai = ai->ai_next)
    {
        if (ai->ai_family == AF_INET)
        {
            auto *sa = reinterpret_cast<sockaddr_in*>(ai->ai_addr);
            if (InetNtopW(AF_INET, &sa->sin_addr, buf4, INET_ADDRSTRLEN))
            {
                uniq.insert(buf4);
            }
        }
        else if (ai->ai_family == AF_INET6)
        {
            auto *sa6 = reinterpret_cast<sockaddr_in6*>(ai->ai_addr);
            if (InetNtopW(AF_INET6, &sa6->sin6_addr, buf6, INET6_ADDRSTRLEN))
            {
                uniq.insert(buf6);
            }
        }
    }
    freeaddrinfo(res);
    if (uniq.empty())
    {
        LOGW("firewallrules") << "Resolution produced no addresses; using literal: " << h;
        return utf8_to_wide(h);
    }
    std::wstring out;
    for (auto it = uniq.begin(); it != uniq.end(); ++it)
    {
        if (!out.empty())
        {
            out = L",";
        }
        out = *it;
    }
    LOGD("firewallrules") << "Resolved RemoteAddresses prepared";
    return out;
}

static int ClientMain(std::string& config)
{
    Logger::Options logger_options;
    logger_options.app_name = "FlowForge";
    logger_options.directory = "logs";
    logger_options.base_filename = "flowforge";
    logger_options.file_min_severity = boost::log::trivial::info;
    logger_options.console_min_severity = boost::log::trivial::debug;

    Logger::Guard logger(logger_options);            // одна инициализация на процесс
    LOGI("client") << "Starting FlowForge";

    if (!IsElevated())
    {
        LOGE("client") << "Please run this with administration rights!";
        return 1;
    }

    std::string tun         = "cvpn0";
    std::string server_ip   = "193.233.23.221";
    int         port        = 5555;
    std::string plugin_path = "./libPlugSRT.so";

    std::string local4 = "10.200.0.2";
    std::string peer4  = "10.200.0.1";
    std::string local6 = "fd00:dead:beef::2";
    std::string peer6  = "fd00:dead:beef::1";
    int mtu = 1400;

    std::vector<std::string> dns_cli = {"10.200.0.1", "1.1.1.1"};
    bool dns_overridden = false;

    LOGD("client") << "Parsing JSON config";

    auto trim_copy = [](const std::string& s) -> std::string
    {
        size_t b = s.find_first_not_of(" \t\r\n");
        if (b == std::string::npos) return std::string();
        size_t e = s.find_last_not_of(" \t\r\n");
        return s.substr(b, e - b + 1);
    };

    auto require_string = [](const boost::json::object& o, const char* key) -> std::string
    {
        if (const boost::json::value* v = o.if_contains(key))
        {
            if (v->is_string())
                return boost::json::value_to<std::string>(*v);
        }
        throw std::runtime_error(std::string("missing or invalid string field '") + key + "'");
    };

    auto require_int = [](const boost::json::object& o, const char* key) -> int
    {
        if (const boost::json::value* v = o.if_contains(key))
        {
            if (v->is_int64())  return static_cast<int>(v->as_int64());
            if (v->is_uint64()) return static_cast<int>(v->as_uint64());
            if (v->is_string())
            {
                const auto s = boost::json::value_to<std::string>(*v);
                try { return std::stoi(s); } catch (...) {}
            }
        }
        throw std::runtime_error(std::string("missing or invalid integer field '") + key + "'");
    };

    boost::json::value jv = boost::json::parse(config);
        if (!jv.is_object())
            throw std::runtime_error("config root must be an object");

    boost::json::object &o = jv.as_object();

        // Обязательные поля (все):
        tun         = require_string(o, "tun");
        server_ip   = require_string(o, "server");
        port        = require_int(o,    "port");
        plugin_path = require_string(o, "plugin");

        local4      = require_string(o, "local4");
        peer4       = require_string(o, "peer4");
        local6      = require_string(o, "local6");
        peer6       = require_string(o, "peer6");

        mtu         = require_int(o,    "mtu");

        // dns: допускаем либо массив строк, либо строку "ip,ip,..."
        dns_cli.clear();
        if (const boost::json::value* dv = o.if_contains("dns"))
        {
            if (dv->is_array())
            {
                for (const boost::json::value& x : dv->as_array())
                {
                    if (!x.is_string())
                        throw std::runtime_error("dns array must contain strings");
                    std::string s = trim_copy(boost::json::value_to<std::string>(x));
                    if (!s.empty()) dns_cli.emplace_back(std::move(s));
                }
            }
            else if (dv->is_string())
            {
                std::string v = boost::json::value_to<std::string>(*dv);
                size_t start = 0;
                while (start < v.size())
                {
                    size_t pos = v.find(',', start);
                    std::string tok = (pos == std::string::npos) ? v.substr(start)
                                                                 : v.substr(start, pos - start);
                    tok = trim_copy(tok);
                    if (!tok.empty()) dns_cli.emplace_back(std::move(tok));
                    if (pos == std::string::npos) break;
                    start = pos + 1;
                }
            }
            else
            {
                throw std::runtime_error("dns must be either array of strings or comma-separated string");
            }
            dns_overridden = true;
        }
        else
        {
            throw std::runtime_error("missing required field 'dns'");
        }

        LOGD("client") << "Args: tun=" << tun << " server=" << server_ip << " port=" << port
                   << " plugin=" << plugin_path
                   << " local4=" << local4 << " peer4=" << peer4
                   << " local6=" << local6 << " peer6=" << peer6
                   << " mtu=" << mtu;

        // Базовая валидация
        if (server_ip.empty())
            throw std::runtime_error("'server' cannot be empty");
        if (port <= 0 || port > 65535)
            throw std::runtime_error("'port' must be in [1..65535]");
        if (mtu < 576 || mtu > 9200)
            throw std::runtime_error("'mtu' must be in [576..9200]");

    server_ip = strip_brackets(server_ip);
    LOGD("client") << "Normalized server: " << server_ip;

    const GUID TUNNEL_TYPE = {0x53bded60, 0xb6c8, 0x49ab, {0x86, 0x12, 0x6f, 0xa5, 0x56, 0x8f, 0xc5, 0x4d}};
    const GUID REQ_GUID    = {0xbaf1c3a1, 0x5175, 0x4a68, {0x9b, 0x4b, 0x2c, 0x3d, 0x6f, 0x1f, 0x00, 0x11}};

    if (!Wintun.load())
    {
        LOGE("tun") << "Failed to load wintun.dll";
        return 1;
    }
    LOGI("tun") << "Loaded wintun.dll";

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        LOGE("client") << "WSAStartup failed";
        return 1;
    }
    LOGD("client") << "WSAStartup OK (2.2)";

    const std::wstring exe_path_w = GetModuleFullPathW();
    const std::wstring fw_addrs_w = ResolveFirewallAddressesW(server_ip);
    FirewallRules::ClientRule cfg{
        .rule_prefix = L"FlowForge",
        .app_path    = exe_path_w,
        .server_ip   = fw_addrs_w
    };
    FirewallRules fw(cfg); // RAII
    LOGI("firewallrules") << "Firewall rules prepared";
    fw.Allow(FirewallRules::Protocol::TCP, port);
    LOGI("firewallrules") << "Allow TCP port " << port;

    LOGD("pluginwrapper") << "Loading plugin: " << plugin_path;
    auto plugin = PluginWrapper::Load(plugin_path);
    if (!plugin.handle)
    {
        LOGE("pluginwrapper") << "Failed to load plugin: " << plugin_path;
        WSACleanup();
        return 1;
    }
    LOGI("pluginwrapper") << "Plugin loaded: " << plugin_path;

    std::wstring wname = utf8_to_wide(tun);
    WINTUN_ADAPTER_HANDLE adapter = Wintun.Open(wname.c_str());
    if (!adapter)
    {
        adapter = Wintun.Create(wname.c_str(), &TUNNEL_TYPE, &REQ_GUID);
        if (!adapter)
        {
            LOGE("tun") << "WintunCreateAdapter failed";
            PluginWrapper::Unload(plugin);
            WSACleanup();
            return 1;
        }
        LOGI("tun") << "Adapter created: " << tun;
    }
    else
    {
        LOGI("tun") << "Adapter opened: " << tun;
    }

    NET_LUID luid{};
    Wintun.GetLuid(adapter, &luid);
    LOGD("tun") << "Adapter LUID acquired";

    // Применить адресный план для Network
    Network::AddressPlan plan;
    plan.local4 = local4;
    plan.peer4  = peer4;
    plan.local6 = local6;
    plan.peer6  = peer6;
    plan.mtu    = static_cast<unsigned long>(mtu);
    Network::SetAddressPlan(plan);

    NetworkRollback rollback(luid, server_ip); // RAII: снимок + авто-откат в деструкторе
    LOGI("networkrollback") << "Baseline snapshot captured (rollback armed)";

    DNS dns(luid);
    std::vector<std::wstring> dns_w;
    dns_w.reserve(dns_cli.size());
    for (const auto &s : dns_cli)
    {
        dns_w.emplace_back(std::wstring(s.begin(), s.end()));
    }
    dns.Apply(dns_w);
    {
        std::ostringstream oss;
        for (size_t i = 0; i < dns_cli.size(); ++i) { if (i) oss << ", "; oss << dns_cli[i]; }
        LOGI("dns") << "Applying DNS: " << oss.str();
    }


    auto reapply = [&]()
    {
        LOGD("netwatcher") << "Reconfiguring routes for server " << server_ip;
        bool v4_ok = false;
        bool v6_ok = false;

        try
        {
            Network::ConfigureNetwork(adapter,
                                      server_ip,
                                      Network::IpVersion::V4);
            v4_ok = true;
            LOGI("netwatcher") << "IPv4 configured";
        }
        catch (const std::exception &e)
        {
            LOGE("netwatcher") << "IPv4 configure failed: " << e.what();
        }

        try
        {
            Network::ConfigureNetwork(adapter,
                                      server_ip,
                                      Network::IpVersion::V6);
            v6_ok = true;
            LOGI("netwatcher") << "IPv6 configured";
        }
        catch (const std::exception &e)
        {
            LOGE("netwatcher") << "IPv6 configure failed: " << e.what();
        }

        if (!v4_ok && !v6_ok)
        {
            LOGF("netwatcher") << "Neither IPv4 nor IPv6 configured";
        }
    };

    NetWatcher nw(reapply, std::chrono::milliseconds(1000));
    LOGD("netwatcher") << "NetWatcher armed (interval=1000ms)";

    WINTUN_SESSION_HANDLE sess = Wintun.Start(adapter, 0x20000);
    if (!sess)
    {
        LOGE("tun") << "WintunStartSession failed";
        Wintun.Close(adapter);
        PluginWrapper::Unload(plugin);
        WSACleanup();
        return 1;
    }
    LOGI("tun") << "Session started (ring=0x20000)";
    LOGI("tun") << "Up: " << tun;

    if (!PluginWrapper::Client_Connect(plugin, o))
    {
        LOGE("pluginwrapper") << "Client_Connect failed";
        Wintun.End(sess);
        Wintun.Close(adapter);
        PluginWrapper::Unload(plugin);
        WSACleanup();
        return 1;
    }
    LOGI("pluginwrapper") << "Connected to " << server_ip << ":" << port;

    auto send_to_net = [sess](const std::uint8_t *data,
                              std::size_t len) -> ssize_t
    {
        debug_packet_info(data, len, "TO_NET");
        BYTE *out = Wintun.AllocSend(sess, static_cast<DWORD>(len));
        if (!out)
        {
            LOGW("tun") << "AllocSend returned null (drop)";
            return 0;
        }
        std::memcpy(out, data, len);
        Wintun.Send(sess, out);
        LOGT("tun") << "TO_NET len=" << len;
        return static_cast<ssize_t>(len);
    };

    auto receive_from_net = [sess](std::uint8_t *buffer,
                                   std::size_t size) -> ssize_t
    {
        DWORD pkt_size = 0;
        BYTE *pkt = Wintun.Recv(sess, &pkt_size);
        if (!pkt)
        {
            LOGT("tun") << "Recv returned null (no packet)";
            return 0;
        }

        debug_packet_info(pkt, pkt_size, "FROM_NET");

        if (pkt_size > size)
        {
            LOGW("tun") << "FROM_NET oversized pkt_size=" << pkt_size << " > buf=" << size;
            Wintun.RecvRelease(sess, pkt);
            return -1;
        }
        std::memcpy(buffer, pkt, pkt_size);
        Wintun.RecvRelease(sess, pkt);
        LOGT("tun") << "FROM_NET len=" << pkt_size;
        return static_cast<ssize_t>(pkt_size);
    };

    LOGI("pluginwrapper") << "Serve loop started";
    int rc = PluginWrapper::Client_Serve(plugin,
                                         receive_from_net,
                                         send_to_net,
                                         &g_working);
    LOGI("pluginwrapper") << "Serve loop exited rc=" << rc;

    LOGD("pluginwrapper") << "Disconnecting client";
    PluginWrapper::Client_Disconnect(plugin);
    LOGD("tun") << "Ending session";
    Wintun.End(sess);
    LOGD("tun") << "Closing adapter";
    Wintun.Close(adapter);
    LOGD("pluginwrapper") << "Unloading plugin";
    PluginWrapper::Unload(plugin);
    LOGD("client") << "WSACleanup";
    WSACleanup();
    LOGI("client") << "Shutdown complete";
    return rc;
}

// Запуск клиента в отдельном потоке.
// cfg - json-данные конфига
EXPORT int32_t Start(char *cfg)
{
    if (g_started.load())
    {
        return -1; // уже запущено
    }

    // Снимем копию аргументов, чтобы не зависеть от времени жизни входных указателей.
    std::string config = cfg;
    g_working = 1;

    g_thread = std::thread([config]() mutable
       {
           ClientMain(config);
           g_started.store(false);
       });

    // Не детачим: хотим корректно join-ить в Stop() (без блокировки вызывающего).
    g_started.store(true);
    return 0;
}

// Мягкая остановка: сигналим рабочему коду и НЕ блокируем вызывающего.
EXPORT int32_t Stop(void)
{
    if (!g_started.load())
    {
        return -2; // не запущено
    }
    g_working = 0;

    // Фоновое ожидание завершения рабочего потока.
    std::thread([]()
    {
        if (g_thread.joinable())
        {
            g_thread.join();
        }
        g_started.store(false);
    }).detach();

    return 0;
}

// Статус работы: 1 — запущен, 0 — остановлен
EXPORT int32_t IsRunning(void)
{
    return g_started.load() ? 1 : 0;
}
