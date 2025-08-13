#include "PluginWrapper.hpp"
#include "Network.hpp"
#include "TUN.hpp"

#include <net/if.h>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>

static volatile sig_atomic_t working = true;

void on_exit(int)
{ working = false; }

int main(int argc, char **argv)
{
    std::string tun         = "cvpn0";
    std::string server_ip   = "193.233.23.221";
    int         port        = 5555;
    std::string plugin_path = "./libPlugUDP.so";

    for (int i = 1; i < argc; ++i)
    {
        std::string a = argv[i];
        if (a == "--tun" && i + 1 < argc) tun = argv[++i];
        else if (a == "--server" && i + 1 < argc) server_ip = argv[++i];
        else if (a == "--port" && i + 1 < argc) port = std::stoi(argv[++i]);
        else if (a == "--plugin" && i + 1 < argc) plugin_path = argv[++i];
        else if (a == "-h" || a == "--help")
        {
            std::cerr << "Usage: Client --server <ip|ipv6> "
                         "[--port 5555] [--tun cvpn0] "
                         "[--plugin ./libPlugUDP.so]\n";
            return 0;
        }
    }

    if (server_ip.empty())
    {
        std::cerr << "Client: --server <ip|ipv6> required\n";
        return 1;
    }

    server_ip = strip_brackets(server_ip);

    PluginWrapper::Plugin plugin = PluginWrapper::Load(plugin_path);
    if (!plugin.handle)
    { return 1; }

    int tun_descriptor = TunAlloc(tun);
    if (tun_descriptor < 0)
    {
        PluginWrapper::Unload(plugin);
        return 1;
    }

    // configure TUN interface
    {
        int ifindex = (int) if_nametoindex(tun.c_str());
        if (ifindex == 0)
        {
            std::fprintf(stderr, "Interface %s not found.\n",
                         tun.c_str());
            return 1;
        }

        if (int rc = if_set_up(tun); rc != 0)
        {
            std::fprintf(stderr, "if_set_up(%s): %s\n",
                         tun.c_str(), std::strerror(-rc));
            return 1;
        }

        if (int rc = if_set_mtu(tun, 1400); rc != 0)
        {
            std::fprintf(stderr, "if_set_mtu(%s): %s (continue)\n",
                         tun.c_str(), std::strerror(-rc));
        }

        write_proc_if_sysctl(tun, "accept_ra",     "0\n");
        write_proc_if_sysctl(tun, "autoconf",      "0\n");
        write_proc_if_sysctl(tun, "disable_ipv6",  "0\n");

        nl_sock *sk = nl_socket_alloc();
        if (!sk)
        {
            std::fprintf(stderr, "nl_socket_alloc failed\n");
            return 1;
        }

        int err = nl_connect(sk, NETLINK_ROUTE);
        if (err < 0) die("nl_connect", err);

        flush_addrs(sk, ifindex, AF_INET);
        flush_addrs(sk, ifindex, AF_INET6);

        add_addr_p2p(sk, ifindex, AF_INET,
                     "10.8.0.2", 32, "10.8.0.1");

        try {
            add_addr_p2p(sk, ifindex, AF_INET6,
                         "fd00:dead:beef::2", 128,
                         "fd00:dead:beef::1");
        }
        catch (...) { /* ignore */ }

        auto gw4 = find_default_gw(sk, AF_INET);
        auto gw6 = find_default_gw(sk, AF_INET6);

        if (is_ipv6_literal(server_ip))
        {
            if (gw6) add_host_route_via_gw(sk, AF_INET6, server_ip, *gw6);
        }
        else
        {
            if (gw4) add_host_route_via_gw(sk, AF_INET, server_ip, *gw4);
        }

        replace_default_via_dev(sk, AF_INET,  ifindex);
        replace_default_via_dev(sk, AF_INET6, ifindex);

        write_proc("/proc/sys/net/ipv6/conf/all/forwarding", "1\n");

        nl_socket_free(sk);
        std::printf("Configured %s. Done.\n", tun.c_str());
    }

    if (!PluginWrapper::Client_Connect(plugin, server_ip,
                                       static_cast<std::uint16_t>(port)))
    {
        close(tun_descriptor);
        PluginWrapper::Unload(plugin);
        return 1;
    }

    int status = fcntl(tun_descriptor, F_GETFL, 0);
    if (status >= 0)
    { fcntl(tun_descriptor, F_SETFL, status | O_NONBLOCK); }

    std::signal(SIGINT,  on_exit);
    std::signal(SIGTERM, on_exit);

    auto send_to_net =
            [tun_descriptor](const std::uint8_t *data,
                             std::size_t len) -> ssize_t
            { return write(tun_descriptor, data, len); };

    auto receive_from_net =
            [tun_descriptor](std::uint8_t *buffer,
                             std::size_t size) -> ssize_t
            {
                ssize_t count = read(tun_descriptor, buffer, size);
                if (count < 0)
                {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
                    return -1;
                }
                return count;
            };

    int rc = PluginWrapper::Client_Serve(plugin,
                                         receive_from_net,
                                         send_to_net,
                                         &working);

    PluginWrapper::Client_Disconnect(plugin);
    close(tun_descriptor);
    PluginWrapper::Unload(plugin);
    return rc;
}
