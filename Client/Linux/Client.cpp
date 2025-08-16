#include "PluginWrapper.hpp"
#include "TUN.hpp"

#include "Network.hpp"

#include <csignal>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>

#include <net/if.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>

static volatile sig_atomic_t working = true;

void on_exit(int) { working = false; }

std::string strip_brackets(std::string s) {
    if (!s.empty() && s.front() == '[' && s.back() == ']')
        return s.substr(1, s.size() - 2);
    return s;
}

int main(int argc, char **argv) {
    std::string tun       = "cvpn0";
    std::string server_ip = "193.233.23.221";
    int         port      = 5555;

    std::string plugin_path = "./libPlugUDP.so";

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--tun" && i + 1 < argc) tun = argv[++i];
        else if (a == "--server" && i + 1 < argc) server_ip = argv[++i];
        else if (a == "--port" && i + 1 < argc) port = std::stoi(argv[++i]);
        else if (a == "--plugin" && i + 1 < argc) plugin_path = argv[++i];
        else if (a == "-h" || a == "--help") {
            std::cerr << "Usage: Client --server <ip|ipv6> "
                         "[--port 5555] [--tun cvpn0] "
                         "[--plugin ./libPlugUDP.so]\n";
            return 0;
        }
    }

    if (server_ip.empty()) {
        std::cerr << "Client: --server <ip|ipv6> required\n";
        return 1;
    }
    server_ip = strip_brackets(server_ip);

    PluginWrapper::Plugin plugin = PluginWrapper::Load(plugin_path);
    if (!plugin.handle) {
        return 1;
    }

    int tun_fd = TunAlloc(tun);
    if (tun_fd < 0) {
        PluginWrapper::Unload(plugin);
        return 1;
    }
    // если твоя сигнатура без server_ip — верни как было: ConfigureNetwork(tun)
    int configured = ConfigureNetwork(tun);
    if (configured != 0) {
        close(tun_fd);
        PluginWrapper::Unload(plugin);
        return 1;
    }

    if (!PluginWrapper::Client_Connect(plugin, server_ip, static_cast<std::uint16_t>(port))) {
        close(tun_fd);
        PluginWrapper::Unload(plugin);
        return 1;
    }

    int status = fcntl(tun_fd, F_GETFL, 0);
    if (status >= 0) fcntl(tun_fd, F_SETFL, status | O_NONBLOCK);

    std::signal(SIGINT,  on_exit);
    std::signal(SIGTERM, on_exit);

    auto send_to_net = [tun_fd](const std::uint8_t* data, std::size_t len) -> ssize_t {
        return ::write(tun_fd, data, len);
    };
    auto receive_from_net = [tun_fd](std::uint8_t* buffer, std::size_t size) -> ssize_t {
        ssize_t n = ::read(tun_fd, buffer, size);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            return -1;
        }
        return n;
    };

    int rc = PluginWrapper::Client_Serve(plugin, receive_from_net, send_to_net, &working);

    PluginWrapper::Client_Disconnect(plugin);

    close(tun_fd);

    PluginWrapper::Unload(plugin);
    return rc;
}
