// Client.cpp — Linux версия с поддержкой NetWatcher и FirewallRules (libnftables)
// Без внешних утилит; логирование через Boost.Log макросы LOG*.

#include "Logger.hpp"
#include "PluginWrapper.hpp"
#include "TUN.hpp"
#include "Network.hpp"
#include "NetWatcher.hpp"
#include "FirewallRules.hpp"
#include "DNS.hpp"
#include "NetworkRollback.hpp"

#include <csignal>
#include <cstdint>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/stat.h>

static volatile sig_atomic_t g_working = 1;

static void OnExit(int)
{
    g_working = 0;
}

static bool IsElevated()
{
    return (::geteuid() == 0);
}

static std::string StripBrackets(const std::string &s)
{
    if (!s.empty() && s.front() == '[' && s.back() == ']')
    {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

static bool IsIpLiteral(const std::string &s)
{
    std::string x = StripBrackets(s);
    in_addr a4{};
    in6_addr a6{};
    return ::inet_pton(AF_INET, x.c_str(), &a4) == 1
           || ::inet_pton(AF_INET6, x.c_str(), &a6) == 1;
}

int main(int argc, char **argv)
{
    Logger::Options log_opts;
    log_opts.app_name             = "FlowForge";
    log_opts.directory            = "logs";
    log_opts.base_filename        = "flowforge";
    log_opts.file_min_severity    = boost::log::trivial::info;
    log_opts.console_min_severity = boost::log::trivial::debug;

    Logger::Guard lg(log_opts);
    LOGI("client") << "Starting FlowForge (Linux)";

    if (!IsElevated())
    {
        LOGE("client") << "Please run as root";
        return 1;
    }

    // Defaults
    std::string tun         = "cvpn0";
    std::string server_ip   = "193.233.23.221";
    int         port        = 5555;
    std::string plugin_path = "./libPlugUDP.so";

    // CLI
    for (int i = 1; i < argc; ++i)
    {
        std::string a = argv[i];
        if (a == "--tun"    && i + 1 < argc) { tun         = argv[++i]; }
        else if (a == "--server" && i + 1 < argc) { server_ip   = argv[++i]; }
        else if (a == "--port"   && i + 1 < argc) { port        = std::stoi(argv[++i]); }
        else if (a == "--plugin" && i + 1 < argc) { plugin_path = argv[++i]; }
        else if (a == "-h" || a == "--help")
        {
            LOGI("client") << "Usage: " << argv[0]
                      << " --server <ip|[ipv6]> [--port 5555] [--tun cvpn0] [--plugin ./libPlugUDP.so]\n";
            return 0;
        }
    }

    if (server_ip.empty())
    {
        LOGE("client") << "--server is required";
        return 1;
    }

    server_ip = StripBrackets(server_ip);
    if (!IsIpLiteral(server_ip))
    {
        LOGE("client") << "--server must be an IP literal for beta (no WAN-DNS bootstrap). Use IPv4 or [IPv6].";
        return 1;
    }
    LOGD("client") << "Server: " << server_ip << " port=" << port << " tun=" << tun;

    NetworkRollback::Params rbp;
    rbp.tun_ifname  = tun;                 // "cvpn0"
    rbp.server_ip   = server_ip;           // "193.233.23.221" или "[2001:db8::1]"
    rbp.revert_v4   = true;
    rbp.revert_v6   = true;
    rbp.flush_addrs = true;

    NetworkRollback rb(rbp);

    // Plugin
    LOGD("pluginwrapper") << "Loading plugin: " << plugin_path;
    auto plugin = PluginWrapper::Load(plugin_path);
    if (!plugin.handle)
    {
        LOGE("pluginwrapper") << "Failed to load plugin";
        return 1;
    }
    LOGI("pluginwrapper") << "Plugin loaded";

    // TUN
    LOGD("tun") << "Opening TUN: " << tun;
    int tun_fd = TunAlloc(tun);
    if (tun_fd < 0)
    {
        LOGE("tun") << "TunAlloc failed";
        PluginWrapper::Unload(plugin);
        return 1;
    }
    int fl = fcntl(tun_fd, F_GETFL, 0);
    if (fl >= 0) { fcntl(tun_fd, F_SETFL, fl | O_NONBLOCK); }
    LOGI("tun") << "Up: " << tun;

    // Firewall: разрешаем только lo, TUN и сервер:порт.
    FirewallRules::Params fw_p;
    fw_p.tun_ifname    = tun;
    fw_p.server_ip     = server_ip;
    fw_p.server_port   = static_cast<std::uint16_t>(port);
    fw_p.allow_udp     = true;
    fw_p.allow_tcp     = true;
    fw_p.hook_priority = 0;

    fw_p.allow_dhcp          = true;
    fw_p.allow_icmp          = true;

    FirewallRules fw(fw_p);
    try
    {
        fw.Apply();
    }
    catch (const std::exception &e)
    {
        LOGE("firewall") << "Apply failed: " << e.what();
    }

    // Network configure (best-effort both families)
    auto ConfigureOnce = [&]() -> bool
    {
        LOGI("network") << "ConfigureNetwork begin";
        int rc = ConfigureNetwork(tun, server_ip);
        if (rc != 0)
        {
            LOGE("network") << "ConfigureNetwork failed rc=" << rc;
            return false;
        }
        LOGI("network") << "ConfigureNetwork done";
        return true;
    };

    if (!ConfigureOnce())
    {
        ::close(tun_fd);
        PluginWrapper::Unload(plugin);
        return 1;
    }


    DNS::Params dns_p;
    dns_p.ifname            = tun;
    dns_p.servers           = { "10.8.0.1" }; // или свой DNS сервера
    dns_p.use_systemd       = true;           // сначала пробуем resolved
    dns_p.make_default_route= true;           // "~." через resolved
    dns_p.resolv_conf_fallback = true;        // разрешить КРАЙНИЙ fallback (безопасно)
    DNS dns(dns_p);
    dns.Apply();


    // NetWatcher: пересобираем маршруты при изменениях в системе
    auto reapply = [&]()
    {
        LOGD("netwatcher") << "Reapply triggered";
        (void)ConfigureOnce();
    };

    NetWatcher watcher(reapply, std::chrono::milliseconds(1000));
    LOGD("netwatcher") << "Armed";

    // Connect
    if (!PluginWrapper::Client_Connect(plugin, server_ip, static_cast<std::uint16_t>(port)))
    {
        LOGE("pluginwrapper") << "Client_Connect failed";
        watcher.Stop();
        try { fw.Revert(); } catch (...) {}
        ::close(tun_fd);
        PluginWrapper::Unload(plugin);
        return 1;
    }
    LOGI("pluginwrapper") << "Connected";

    std::signal(SIGINT,  OnExit);
    std::signal(SIGTERM, OnExit);
    LOGD("client") << "Signal handlers installed";

    auto SendToNet = [tun_fd](const std::uint8_t* data, std::size_t len) -> ssize_t
    {
        ssize_t wr = ::write(tun_fd, data, len);
        if (wr < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) { return 0; }
        if (wr < 0)
        {
            LOGW("tun") << "write() failed: " << std::strerror(errno);
            return -1;
        }
        LOGT("tun") << "TO_NET len=" << wr;
        return wr;
    };

    auto RecvFromNet = [tun_fd](std::uint8_t* buf, std::size_t cap) -> ssize_t
    {
        ssize_t rd = ::read(tun_fd, buf, cap);
        if (rd < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) { return 0; }
        if (rd < 0)
        {
            LOGW("tun") << "read() failed: " << std::strerror(errno);
            return -1;
        }
        LOGT("tun") << "FROM_NET len=" << rd;
        return rd;
    };

    LOGI("pluginwrapper") << "Serve begin";
    int rc = PluginWrapper::Client_Serve(plugin, RecvFromNet, SendToNet, &g_working);
    LOGI("pluginwrapper") << "Serve end rc=" << rc;

    PluginWrapper::Client_Disconnect(plugin);
    watcher.Stop();

    ::close(tun_fd);
    PluginWrapper::Unload(plugin);

    LOGI("client") << "Shutdown complete";
    return rc;
}
