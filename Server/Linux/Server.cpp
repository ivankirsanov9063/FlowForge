// Server.cpp — серверная часть: TUN, NAT/MSS, плагин транспорта

#include "PluginWrapper.hpp"
#include "TUN.hpp"
#include "Network.hpp"
#include "NetworkRollback.hpp"
#include "NetWatcher.hpp"

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
        }
        else if (a == "--port" && i + 1 < argc)
        {
            port = std::stoi(argv[++i]);
        }
        else if (a == "--plugin" && i + 1 < argc)
        {
            plugin_path = argv[++i];
        }
        else if (a == "--cidr4" && i + 1 < argc)
        {
            cidr4 = argv[++i];
        }
        else if (a == "--cidr6" && i + 1 < argc)
        {
            cidr6 = argv[++i];
        }
        else if (a == "--nat44" && i + 1 < argc)
        {
            nat44_src = argv[++i];
        }
        else if (a == "--nat66" && i + 1 < argc)
        {
            nat66_src = argv[++i];
        }
        else if (a == "--mtu" && i + 1 < argc)
        {
            mtu = std::stoi(argv[++i]);
        }
        else if (a == "--no-nat")
        {
            with_nat_fw = false;
        }
        else if (a == "-h" || a == "--help")
        {
            std::cerr
                << "Usage: Server [--port 5555] [--tun svpn0] [--plugin ./libPlugUDP.so]\n"
                   "              [--cidr4 10.8.0.1/24] [--cidr6 fd00:dead:beef::1/64]\n"
                   "              [--nat44 <CIDR>] [--nat66 <CIDR>] [--mtu 1400] [--no-nat]\n";
            return 0;
        }
    }

    if (geteuid() != 0)
    {
        std::cerr << "Требуются права root.\n";
        return 1;
    }

    PluginWrapper::Plugin plugin = PluginWrapper::Load(plugin_path);
    if (!plugin.handle)
    {
        return 1;
    }

    int tun_fd = TunAlloc(tun);
    if (tun_fd < 0)
    {
        PluginWrapper::Unload(plugin);
        return 1;
    }

    NetworkRollback network_rollback{};

    // Сформировать Params из CLI
    NetConfig::Params p{};
    p.mtu = mtu;

    if (!NetConfig::parse_cidr4(cidr4, p.v4_local))
    {
        std::cerr << "Invalid --cidr4: " << cidr4 << "\n";
        close(tun_fd);
        PluginWrapper::Unload(plugin);
        return 1;
    }
    if (!NetConfig::parse_cidr6(cidr6, p.v6_local))
    {
        std::cerr << "Invalid --cidr6: " << cidr6 << "\n";
        close(tun_fd);
        PluginWrapper::Unload(plugin);
        return 1;
    }

    // CIDR источника для NAT: задан пользователем или берём сеть TUN
    p.nat44_src = !nat44_src.empty() ? nat44_src : NetConfig::to_network_cidr(p.v4_local);
    p.nat66_src = !nat66_src.empty() ? nat66_src : NetConfig::to_network_cidr(p.v6_local);

    if (with_nat_fw && !NetConfig::nft_feature_probe())
    {
        throw std::runtime_error(
            "This platform doesn't support nftables."
            "You can add --no-nat option to fix this mistake and to disable support of NAT");
    }

    // Применяем сетевую конфигурацию
    try
    {
        NetConfig::ApplyServerSide(tun, p, with_nat_fw);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Network setup failed: " << e.what() << "\n";
        close(tun_fd);
        PluginWrapper::Unload(plugin);
        return 1;
    }

    // Вотчер за default route: при смене WAN пересоберёт NAT/MSS
    // NetWatcher нужен только при NAT/MSS. В режиме --no-nat не запускаем.
    std::unique_ptr<NetWatcher> watcher;
    if (with_nat_fw)
    {
        watcher = std::make_unique<NetWatcher>(p);
    }

    if (!PluginWrapper::Server_Bind(
            plugin,
            static_cast<std::uint16_t>(port)))
    {
        close(tun_fd);
        PluginWrapper::Unload(plugin);
        return 1;
    }

    int status = fcntl(tun_fd, F_GETFL, 0);
    if (status >= 0)
    {
        fcntl(tun_fd, F_SETFL, status | O_NONBLOCK);
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

    PluginWrapper::Server_Serve(
        plugin,
        receive_from_net,
        send_to_net,
        &working);

    close(tun_fd);
    PluginWrapper::Unload(plugin);
    return 0;
}
