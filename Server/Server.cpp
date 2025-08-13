#include "PluginWrapper.hpp"
#include "TUN.hpp"
#include "Network.hpp"

#include <csignal>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <fcntl.h>
#include <functional>
#include <iostream>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>

static volatile sig_atomic_t working = true;
void on_exit(int) { working = false; }

int main(int argc, char** argv)
{
    std::string tun = "svpn0";
    int port = 5555;
    std::string plugin_path = "./libPlugUDP.so";

    for (int i = 1; i < argc; ++i)
    {
        std::string a = argv[i];
        if (a == "--tun" && i + 1 < argc) tun = argv[++i];
        else if (a == "--port" && i + 1 < argc) port = std::stoi(argv[++i]);
        else if (a == "--plugin" && i + 1 < argc) plugin_path = argv[++i];
        else if (a == "-h" || a == "--help")
        {
            std::cerr << "Usage: Server [--port 5555] [--tun svpn0] [--plugin ./libPlugUDP.so]\n";
            return 0;
        }
    }

    PluginWrapper::Plugin plugin = PluginWrapper::Load(plugin_path);
    if (!plugin.handle) return 1;

    int tun_fd = TunAlloc(tun);
    if (tun_fd < 0) { PluginWrapper::Unload(plugin); return 1; }

    // 👉 передаём имя TUN в скрипт
    {
        if (!NetConfig::ApplyServerSide(tun)) {
            std::cerr << "Network setup failed\n";
            close(tun_fd);
            PluginWrapper::Unload(plugin);
            return 1;
        }
    }

    if (!PluginWrapper::Server_Bind(plugin, static_cast<std::uint16_t>(port)))
    {
        close(tun_fd);
        PluginWrapper::Unload(plugin);
        return 1;
    }

    int status = fcntl(tun_fd, F_GETFL, 0);
    if (status >= 0) { fcntl(tun_fd, F_SETFL, status | O_NONBLOCK); }

    auto send_to_net = [tun_fd](const std::uint8_t* data, std::size_t len) -> ssize_t {
        return write(tun_fd, data, len);
    };
    auto receive_from_net = [tun_fd](std::uint8_t* buffer, std::size_t size) -> ssize_t {
        ssize_t count = read(tun_fd, buffer, size);
        if (count < 0) { if (errno == EAGAIN || errno == EWOULDBLOCK) return 0; return -1; }
        return count;
    };

    std::signal(SIGINT,  on_exit);
    std::signal(SIGTERM, on_exit);

    PluginWrapper::Server_Serve(plugin, receive_from_net, send_to_net, &working);

    close(tun_fd);
    PluginWrapper::Unload(plugin);
}
