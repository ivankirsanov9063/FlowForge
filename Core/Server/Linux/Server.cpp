// Server.cpp — серверная часть: TUN, NAT/MSS, плагин транспорта

#include "Core/PluginWrapper.hpp"
#include "Core/TUN.hpp"
#include "Network.hpp"
#include "NetworkRollback.hpp"
#include "NetWatcher.hpp"
#include "Core/Logger.hpp"

#include <csignal>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <cstdint>

static volatile sig_atomic_t working = true;

void on_exit(int)
{
    working = false;
}

int main(int argc,
         char **argv)
{
    Logger::Options logger_options;
    logger_options.app_name = "FlowForge";
    logger_options.directory = "logs";
    logger_options.base_filename = "flowforge";
    logger_options.file_min_severity = boost::log::trivial::info;
    logger_options.console_min_severity = boost::log::trivial::debug;

    Logger::Guard logger(logger_options);
    LOGI("server") << "Startup: begin, argc=" << argc;

    std::string tun         = "svpn0";
    int         port        = 5555;
    std::string plugin_path = "./libPlugUDP.so";

    // Параметры адресации/NAT — задаются флагами
    std::string cidr4       = "10.8.0.1/24";
    std::string cidr6       = "fd00:dead:beef::1/64";
    std::string nat44_src; // если пусто — возьмём сеть из cidr4
    std::string nat66_src; // если пусто — возьмём сеть из cidr6
    int         mtu         = 1400;
    bool        with_nat_fw = true;

    for (int i = 1; i < argc; ++i)
    {
        std::string a = argv[i];
        if (a == "--tun" && i + 1 < argc)
        {
            tun = argv[++i];
            LOGD("server") << "Arg: --tun " << tun;
        }
        else if (a == "--port" && i + 1 < argc)
        {
            port = std::stoi(argv[++i]);
            LOGD("server") << "Arg: --port " << port;
        }
        else if (a == "--plugin" && i + 1 < argc)
        {
            plugin_path = argv[++i];
            LOGD("server") << "Arg: --plugin " << plugin_path;
        }
        else if (a == "--cidr4" && i + 1 < argc)
        {
            cidr4 = argv[++i];
            LOGD("server") << "Arg: --cidr4 " << cidr4;
        }
        else if (a == "--cidr6" && i + 1 < argc)
        {
            cidr6 = argv[++i];
            LOGD("server") << "Arg: --cidr6 " << cidr6;
        }
        else if (a == "--nat44" && i + 1 < argc)
        {
            nat44_src = argv[++i];
            LOGD("server") << "Arg: --nat44 " << nat44_src;
        }
        else if (a == "--nat66" && i + 1 < argc)
        {
            nat66_src = argv[++i];
            LOGD("server") << "Arg: --nat66 " << nat66_src;
        }
        else if (a == "--mtu" && i + 1 < argc)
        {
            mtu = std::stoi(argv[++i]);
            LOGD("server") << "Arg: --mtu " << mtu;
        }
        else if (a == "--no-nat")
        {
            with_nat_fw = false;
            LOGD("server") << "Arg: --no-nat (NAT/MSS/FW disabled)";
        }
        else if (a == "-h" || a == "--help")
        {
            LOGI("server")
                << "Usage: Server [--port 5555] [--tun svpn0] [--plugin ./libPlugUDP.so]\n"
                   "              [--cidr4 10.8.0.1/24] [--cidr6 fd00:dead:beef::1/64]\n"
                   "              [--nat44 <CIDR>] [--nat66 <CIDR>] [--mtu 1400] [--no-nat]\n";
            LOGI("server") << "Help displayed";
            return 0;
        }
    }

    LOGI("server") << "Args: tun=" << tun
                   << " port=" << port
                   << " plugin=" << plugin_path
                   << " cidr4=" << cidr4
                   << " cidr6=" << cidr6
                   << " nat44=" << (nat44_src.empty() ? "<auto>" : nat44_src)
                   << " nat66=" << (nat66_src.empty() ? "<auto>" : nat66_src)
                   << " mtu=" << mtu
                   << " nat/fw=" << (with_nat_fw ? "on" : "off");

    PluginWrapper::Plugin plugin{}; // для корректной выгрузки в случае исключений
    bool plugin_loaded = false;
    int  tun_fd        = -1;

    try
    {
        if (geteuid() != 0)
        {
            LOGE("server") << "Privilege check failed: root required";
            throw std::runtime_error("Root privileges are required.");
        }

        LOGI("server") << "Plugin: loading " << plugin_path;
        plugin = PluginWrapper::Load(plugin_path);
        if (!plugin.handle)
        {
            LOGE("server") << "Plugin: load failed for " << plugin_path;
            throw std::runtime_error("Failed to load plugin: " + plugin_path);
        }
        plugin_loaded = true;
        LOGD("server") << "Plugin: loaded ok";

        LOGI("server") << "TUN: creating interface " << tun;
        tun_fd = TunAlloc(tun);
        if (tun_fd < 0)
        {
            LOGE("server") << "TUN: create failed for " << tun;
            throw std::runtime_error("Failed to create TUN interface: " + tun);
        }
        LOGI("server") << "TUN up: " << tun;

        LOGD("server") << "NetworkRollback: snapshot baseline";
        NetworkRollback network_rollback{};
        if (!network_rollback.Ok())
        {
            LOGE("server") << "NetworkRollback: snapshot failed";
            throw std::runtime_error("Failed to snapshot network baseline for rollback.");
        }

        NetConfig::Params p{};
        p.mtu = mtu;

        LOGT("server") << "Parse: cidr4=" << cidr4;
        if (!NetConfig::parse_cidr4(cidr4, p.v4_local))
        {
            LOGE("server") << "Parse: invalid --cidr4 " << cidr4;
            throw std::invalid_argument("Invalid --cidr4: " + cidr4);
        }
        LOGT("server") << "Parse: cidr6=" << cidr6;
        if (!NetConfig::parse_cidr6(cidr6, p.v6_local))
        {
            LOGE("server") << "Parse: invalid --cidr6 " << cidr6;
            throw std::invalid_argument("Invalid --cidr6: " + cidr6);
        }

        p.nat44_src = !nat44_src.empty() ? nat44_src : NetConfig::to_network_cidr(p.v4_local);
        p.nat66_src = !nat66_src.empty() ? nat66_src : NetConfig::to_network_cidr(p.v6_local);
        LOGD("server") << "NAT sources: v4=" << p.nat44_src << " v6=" << p.nat66_src;

        if (with_nat_fw && !NetConfig::nft_feature_probe())
        {
            LOGE("server") << "nftables probe failed (NAT/MSS requested)";
            throw std::runtime_error(
                "This platform doesn't support nftables. "
                "Use --no-nat to disable NAT/MSS features.");
        }

        LOGI("server") << "Apply network: server-side config";
        NetConfig::ApplyServerSide(tun, p, with_nat_fw);
        LOGI("server") << "Apply network: done";

        std::unique_ptr<NetWatcher> watcher;
        if (with_nat_fw)
        {
            LOGI("server") << "NetWatcher: starting";
            watcher = std::make_unique<NetWatcher>(p);
        }

        LOGI("server") << "Binding server: port=" << port;
        if (!PluginWrapper::Server_Bind(
                plugin,
                static_cast<std::uint16_t>(port)))
        {
            LOGE("server") << "Bind: failed on port " << port;
            throw std::runtime_error("Failed to bind server on port " + std::to_string(port));
        }
        LOGI("server") << "Bind: ok";

        int status = fcntl(tun_fd, F_GETFL, 0);
        if (status >= 0)
        {
            fcntl(tun_fd, F_SETFL, status | O_NONBLOCK);
            LOGD("server") << "TUN: set non-blocking";
        }
        else
        {
            LOGW("server") << "TUN: F_GETFL failed (non-blocking not set)";
        }

        auto send_to_net = [tun_fd](const std::uint8_t *data,
                                    std::size_t        len) -> ssize_t
        {
            return write(tun_fd, data, len);
        };

        auto receive_from_net = [tun_fd](std::uint8_t *buffer,
                                         std::size_t   size) -> ssize_t
        {
            ssize_t count = read(tun_fd, buffer, size);
            if (count < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    return 0;
                }
                return -1;
            }
            return count;
        };

        std::signal(SIGINT, on_exit);
        std::signal(SIGTERM, on_exit);
        LOGI("server") << "Signals: handlers installed (SIGINT/SIGTERM)";

        LOGI("server") << "Serve: entering loop";
        PluginWrapper::Server_Serve(
            plugin,
            receive_from_net,
            send_to_net,
            &working);
        LOGI("server") << "Serve: exited";

        if (tun_fd >= 0)
        {
            LOGD("server") << "Cleanup: closing TUN";
            close(tun_fd);
            tun_fd = -1;
        }
        if (plugin_loaded)
        {
            LOGD("server") << "Cleanup: unloading plugin";
            PluginWrapper::Unload(plugin);
            plugin_loaded = false;
        }
        LOGI("server") << "Shutdown: success";
        return 0;
    }
    catch (const std::exception &e)
    {
        LOGE("server") << "Fatal: " << e.what();
        if (tun_fd >= 0)
        {
            LOGD("server") << "Cleanup on error: closing TUN";
            close(tun_fd);
            tun_fd = -1;
        }
        if (plugin_loaded)
        {
            LOGD("server") << "Cleanup on error: unloading plugin";
            PluginWrapper::Unload(plugin);
            plugin_loaded = false;
        }
        LOGI("server") << "Shutdown: error path";
        return 1;
    }
}
