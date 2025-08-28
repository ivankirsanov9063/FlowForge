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

static int ClientMain(int argc, char **argv)
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

    std::string tun = "cvpn0";
    std::string server_ip = "193.233.23.221";
    int port = 5555;
    std::string plugin_path = "PlugUDP.dll";

    // Address plan defaults (можно переопределить через CLI)
    std::string local4 = "10.8.0.2";
    std::string peer4  = "10.8.0.1";
    std::string local6 = "fd00:dead:beef::2";
    std::string peer6  = "fd00:dead:beef::1";
    int mtu = 1400;
    // DNS по умолчанию; если указать --dns, список заменится/расширится
    std::vector<std::string> dns_cli = {"10.8.0.1", "1.1.1.1"};
    bool dns_overridden = false;

    LOGD("client") << "Parsing CLI arguments";
    for (int i = 0; i < argc; ++i)
    {
        std::string a = argv[i];
        if (a == "--tun" && i + 1 < argc)
        {
            tun = argv[++i];
        }
        else if (a == "--server" && i + 1 < argc)
        {
            server_ip = argv[++i];
        }
        else if (a == "--port" && i + 1 < argc)
        {
            port = std::stoi(argv[++i]);
        }
        else if (a == "--plugin" && i + 1 < argc)
        {
            plugin_path = argv[++i];
        }
        else if (a == "--local4" && i + 1 < argc)
        {
            local4 = argv[++i];
        }
        else if (a == "--peer4" && i + 1 < argc)
        {
            peer4 = argv[++i];
        }
        else if (a == "--local6" && i + 1 < argc)
        {
            local6 = argv[++i];
        }
        else if (a == "--peer6" && i + 1 < argc)
        {
            peer6 = argv[++i];
        }
        else if (a == "--mtu" && i + 1 < argc)
        {
            mtu = std::stoi(argv[++i]);
        }
        else if (a == "--dns" && i + 1 < argc)
        {
            std::string v = argv[++i];
            if (!dns_overridden) { dns_cli.clear(); dns_overridden = true; }
            // split by comma; пробелы с краёв — убрать
            size_t start = 0;
            while (start < v.size())
            {
                size_t pos = v.find(',', start);
                std::string tok = (pos == std::string::npos) ? v.substr(start) : v.substr(start, pos - start);
                if (!tok.empty())
                {
                    size_t b = tok.find_first_not_of(" \t");
                    size_t e = tok.find_last_not_of(" \t");
                    if (b != std::string::npos)
                    {
                        dns_cli.emplace_back(tok.substr(b, e - b + 1));
                    }
                }
                if (pos == std::string::npos) break;
                start = pos + 1;
            }
        }
        else if (a == "-h" || a == "--help")
        {
            LOGI("client") << "Usage: Client --server <ip|ipv6> [--port 5555] [--tun cvpn0] "
                              "[--plugin PlugUDP.dll] [--local4 A.B.C.D] [--peer4 A.B.C.D] "
                              "[--local6 ::addr] [--peer6 ::addr] [--mtu 1400] [--dns ip[,ip...]]";

            return 0;
        }
    }

    LOGD("client") << "Args: tun=" << tun << " server=" << server_ip << " port=" << port
                   << " plugin=" << plugin_path
                   << " local4=" << local4 << " peer4=" << peer4
                   << " local6=" << local6 << " peer6=" << peer6
                   << " mtu=" << mtu;

    if (server_ip.empty())
    {
        LOGE("client") << "Client: --server <ip|ipv6> required";
        return 1;
    }

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
    fw.Allow(FirewallRules::Protocol::UDP, port);
    LOGI("firewallrules") << "Allow UDP port " << port;

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

    if (!PluginWrapper::Client_Connect(plugin,
                                       server_ip,
                                       static_cast<std::uint16_t>(port)))
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
// Ожидается, что argv/len — это ТОЛЬКО аргументы (без argv[0]).
EXPORT int32_t Start(char **argv, int32_t len)
{
    if (g_started.load())
    {
        return -1; // уже запущено
    }

    // Снимем копию аргументов, чтобы не зависеть от времени жизни входных указателей.
    std::vector<std::string> args;

    if (argv && len > 0)
    {
        args.reserve(static_cast<size_t>(len) + 1);
        for (int32_t i = 0; i < len; ++i)
        {
            if (argv[i] && *argv[i])
            {
                args.emplace_back(argv[i]);
            }
        }
    }
    g_working = 1;

    g_thread = std::thread([args]() mutable
       {
           std::vector<char *> cargs;
           cargs.reserve(args.size());
           for (auto &s: args)
           {
               // безопасно: строки живут до конца лямбды
               cargs.push_back(const_cast<char *>(s.c_str()));
           }

           ClientMain(static_cast<int>(cargs.size()), cargs.data());
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
