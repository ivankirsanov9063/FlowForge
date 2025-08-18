#include "PluginWrapper.hpp"
#include "TUN.hpp"
#include "Network.hpp"
#include "FirewallRules.hpp"
#include "NetWatcher.hpp"
#include "DNS.hpp"
#include "NetworkRollback.hpp"

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

static volatile sig_atomic_t working = true;

static void on_exit(int)
{
    working = false;
}

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
        std::printf(
            "[%s] IPv4: %u.%u.%u.%u -> %u.%u.%u.%u (len=%zu)\n",
            direction,
            (src >> 24) & 0xff,
            (src >> 16) & 0xff,
            (src >> 8) & 0xff,
            src & 0xff,
            (dst >> 24) & 0xff,
            (dst >> 16) & 0xff,
            (dst >> 8) & 0xff,
            dst & 0xff,
            len
        );
    }
    else if (version == 6)
    {
        std::printf("[%s] IPv6 packet (len=%zu)\n", direction, len);
    }
    else
    {
        std::printf("[%s] Unknown packet version=%d (len=%zu)\n", direction, version, len);
    }
}

bool IsElevated() noexcept
{
    HANDLE h_token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &h_token))
    {
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
    std::wstring path(MAX_PATH, L'\0');
    DWORD n = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (n == 0)
    {
        throw std::runtime_error("GetModuleFileNameW failed");
    }
    if (n >= path.size())
    {
        std::wstring big(4096, L'\0');
        n = GetModuleFileNameW(nullptr, big.data(), static_cast<DWORD>(big.size()));
        if (n == 0 || n >= big.size())
        {
            throw std::runtime_error("GetModuleFileNameW failed (long path)");
        }
        big.resize(n);
        return big;
    }
    path.resize(n);
    return path;
}

/**
 * @brief Резолвит хост/адрес в список IPv4/IPv6 адресов для поля Firewall RemoteAddresses.
 *        Возвращает CSV-строку адресов без пробелов (поддерживает IPv6).
 *        Если резолв не удался — возвращает исходную строку (без скобок).
 */
static std::wstring ResolveFirewallAddressesW(const std::string &host)
{
    std::string h = strip_brackets(host);
    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo *res = nullptr;
    if (getaddrinfo(h.c_str(), nullptr, &hints, &res) != 0)
    {
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
    return out;
}

int main(int argc,
         char **argv)
{
    if (!IsElevated())
    {
        std::cerr << "Please run this with administration rights!\n";
        return 1;
    }

    std::string tun = "cvpn0";
    std::string server_ip = "193.233.23.221";
    int port = 5555;
    std::string plugin_path = "PlugUDP.dll";

    for (int i = 1; i < argc; ++i)
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
        else if (a == "-h" || a == "--help")
        {
            std::cerr << "Usage: Client --server <ip|ipv6> [--port 5555] [--tun cvpn0] [--plugin PlugUDP.dll]\n";
            return 0;
        }
    }

    if (server_ip.empty())
    {
        std::cerr << "Client: --server <ip|ipv6> required\n";
        return 1;
    }

    server_ip = strip_brackets(server_ip);

    const GUID TUNNEL_TYPE = {0x53bded60, 0xb6c8, 0x49ab, {0x86, 0x12, 0x6f, 0xa5, 0x56, 0x8f, 0xc5, 0x4d}};
    const GUID REQ_GUID    = {0xbaf1c3a1, 0x5175, 0x4a68, {0x9b, 0x4b, 0x2c, 0x3d, 0x6f, 0x1f, 0x00, 0x11}};

    if (!Wintun.load())
    {
        std::cerr << "Failed to load wintun.dll\n";
        return 1;
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }

    const std::wstring exe_path_w = GetModuleFullPathW();
    const std::wstring fw_addrs_w = ResolveFirewallAddressesW(server_ip);
    FirewallRules::ClientRule cfg{
        .rule_prefix = L"FlowForge",
        .app_path    = exe_path_w,
        .server_ip   = fw_addrs_w
    };
    FirewallRules fw(cfg); // RAII
    fw.Allow(FirewallRules::Protocol::UDP, port);

    auto plugin = PluginWrapper::Load(plugin_path);
    if (!plugin.handle)
    {
        WSACleanup();
        return 1;
    }

    std::wstring wname = utf8_to_wide(tun);
    WINTUN_ADAPTER_HANDLE adapter = Wintun.Open(wname.c_str());
    if (!adapter)
    {
        adapter = Wintun.Create(wname.c_str(), &TUNNEL_TYPE, &REQ_GUID);
        if (!adapter)
        {
            std::cerr << "WintunCreateAdapter failed\n";
            PluginWrapper::Unload(plugin);
            WSACleanup();
            return 1;
        }
    }

    NET_LUID luid{};
    Wintun.GetLuid(adapter, &luid);
    NetworkRollback rollback(luid, server_ip); // RAII: снимок + авто-откат в деструкторе

    DNS dns(luid);
    dns.Apply({L"10.8.0.1", L"1.1.1.1"});

    auto reapply = [&]()
    {
        bool v4_ok = false;
        bool v6_ok = false;

        try
        {
            Network::ConfigureNetwork(adapter,
                                      server_ip,
                                      Network::IpVersion::V4);
            v4_ok = true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "[reapply] IPv4 configure failed: " << e.what() << "\n";
        }

        try
        {
            Network::ConfigureNetwork(adapter,
                                      server_ip,
                                      Network::IpVersion::V6);
            v6_ok = true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "[reapply] IPv6 configure failed: " << e.what() << "\n";
        }

        if (!v4_ok && !v6_ok)
        {
            std::cerr << "[reapply] FATAL: neither IPv4 nor IPv6 configured\n";
        }
    };


    reapply();
    NetWatcher nw(reapply, std::chrono::milliseconds(1500));

    WINTUN_SESSION_HANDLE sess = Wintun.Start(adapter, 0x20000);
    if (!sess)
    {
        std::cerr << "WintunStartSession failed\n";
        Wintun.Close(adapter);
        PluginWrapper::Unload(plugin);
        WSACleanup();
        return 1;
    }

    std::cout << "Wintun up: " << tun << "\n";

    if (!PluginWrapper::Client_Connect(plugin,
                                       server_ip,
                                       static_cast<std::uint16_t>(port)))
    {
        std::cerr << "Client_Connect failed\n";
        Wintun.End(sess);
        Wintun.Close(adapter);
        PluginWrapper::Unload(plugin);
        WSACleanup();
        return 1;
    }

    std::signal(SIGINT, on_exit);
    std::signal(SIGTERM, on_exit);

    auto send_to_net = [sess](const std::uint8_t *data,
                              std::size_t len) -> ssize_t
    {
        debug_packet_info(data, len, "TO_NET");
        BYTE *out = Wintun.AllocSend(sess, static_cast<DWORD>(len));
        if (!out)
        {
            return 0;
        }
        std::memcpy(out, data, len);
        Wintun.Send(sess, out);
        return static_cast<ssize_t>(len);
    };

    auto receive_from_net = [sess](std::uint8_t *buffer,
                                   std::size_t size) -> ssize_t
    {
        DWORD pkt_size = 0;
        BYTE *pkt = Wintun.Recv(sess, &pkt_size);
        if (!pkt)
        {
            return 0;
        }

        debug_packet_info(pkt, pkt_size, "FROM_NET");

        if (pkt_size > size)
        {
            Wintun.RecvRelease(sess, pkt);
            return -1;
        }
        std::memcpy(buffer, pkt, pkt_size);
        Wintun.RecvRelease(sess, pkt);
        return static_cast<ssize_t>(pkt_size);
    };

    int rc = PluginWrapper::Client_Serve(plugin,
                                         receive_from_net,
                                         send_to_net,
                                         &working);

    PluginWrapper::Client_Disconnect(plugin);
    Wintun.End(sess);
    Wintun.Close(adapter);
    PluginWrapper::Unload(plugin);
    WSACleanup();
    return rc;
}
