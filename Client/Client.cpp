#include "PluginWrapper.hpp"
#include "Network.hpp"
#include "TUN.hpp"

#include <csignal>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>

#ifdef __linux__
  #include <net/if.h>
  #include <cerrno>
  #include <fcntl.h>
  #include <sys/socket.h>
  #include <unistd.h>
  #include <linux/if.h>
  #include <linux/if_tun.h>
#else
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <io.h>
  #include <fcntl.h>
#endif

static volatile sig_atomic_t working = true;
void on_exit(int) { working = false; }

int main(int argc, char **argv)
{
    std::string tun         = "cvpn0";
    std::string server_ip   = "193.233.23.221";
    int         port        = 5555;
#ifdef _WIN32
    std::string plugin_path = "./PlugUDP.dll";
#else
    std::string plugin_path = "./libPlugUDP.so";
#endif

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        std::fprintf(stderr, "WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }
#endif


    // ... (парсинг аргументов как у тебя)

    server_ip = strip_brackets(server_ip);

    auto plugin = PluginWrapper::Load(plugin_path);
    if (!plugin.handle) return 1;

    int tun_descriptor = TunAlloc(tun); // см. примечание ниже про Windows
    if (tun_descriptor < 0)
    { PluginWrapper::Unload(plugin); return 1; }

    // --- СЕТЕВАЯ КОНФИГУРАЦИЯ ИНТЕРФЕЙСА И МАРШРУТОВ ---
#ifdef __linux__
    {
        int ifindex = (int) if_nametoindex(tun.c_str());
        if (ifindex == 0)
        {
            std::fprintf(stderr, "Interface %s not found.\n", tun.c_str());
            return 1;
        }

        if (int rc = if_set_up(tun); rc != 0)
        {
            std::fprintf(stderr, "if_set_up(%s): %s\n", tun.c_str(), std::strerror(-rc));
            return 1;
        }

        if (int rc = if_set_mtu(tun, 1400); rc != 0)
        {
            std::fprintf(stderr, "if_set_mtu(%s): %s (continue)\n", tun.c_str(), std::strerror(-rc));
        }

        write_proc_if_sysctl(tun, "accept_ra",     "0\n");
        write_proc_if_sysctl(tun, "autoconf",      "0\n");
        write_proc_if_sysctl(tun, "disable_ipv6",  "0\n");

        nl_sock *sk = nl_socket_alloc();
        if (!sk) { std::fprintf(stderr, "nl_socket_alloc failed\n"); return 1; }
        if (int err = nl_connect(sk, NETLINK_ROUTE); err < 0)
        { std::fprintf(stderr, "nl_connect: %s\n", nl_geterror(err)); return 1; }

        flush_addrs(sk, ifindex, AF_INET);
        flush_addrs(sk, ifindex, AF_INET6);

        add_addr_p2p(sk, ifindex, AF_INET,  "10.8.0.2", 32,  "10.8.0.1");
        try { add_addr_p2p(sk, ifindex, AF_INET6, "fd00:dead:beef::2", 128, "fd00:dead:beef::1"); } catch (...) {}

        auto gw4 = find_default_gw(sk, AF_INET);
        auto gw6 = find_default_gw(sk, AF_INET6);
        if (is_ipv6_literal(server_ip)) { if (gw6) add_host_route_via_gw(sk, AF_INET6, server_ip, *gw6); }
        else                             { if (gw4) add_host_route_via_gw(sk, AF_INET,  server_ip, *gw4); }

        replace_default_via_dev(sk, AF_INET,  ifindex);
        replace_default_via_dev(sk, AF_INET6, ifindex);

        write_proc("/proc/sys/net/ipv6/conf/all/forwarding", "1\n");

        nl_socket_free(sk);
        std::printf("Configured %s (Linux). Done.\n", tun.c_str());
    }
#else
    {
        if (int rc = if_set_up(tun); rc != 0)
            std::fprintf(stderr, "if_set_up(%s) failed: %d\n", tun.c_str(), rc);

        (void)if_set_mtu(tun, 1400);

        flush_addrs_win(tun, AF_INET);
        flush_addrs_win(tun, AF_INET6);

        try {
            add_addr_p2p_win(tun, AF_INET,  "10.8.0.2", 32,  "10.8.0.1");
            add_addr_p2p_win(tun, AF_INET6, "fd00:dead:beef::2", 128, "fd00:dead:beef::1");
        } catch (...) {}

        set_interface_metric_win(tun, AF_INET,  1);
        set_interface_metric_win(tun, AF_INET6, 1);

        auto gw4 = find_default_gw_win(AF_INET);
        auto gw6 = find_default_gw_win(AF_INET6);
        if (is_ipv6_literal(server_ip)) { if (gw6) add_host_route_via_gw_win(AF_INET6, server_ip, *gw6); }
        else                             { if (gw4) add_host_route_via_gw_win(AF_INET,  server_ip, *gw4); }

        replace_default_via_dev_win(AF_INET,  tun, "10.8.0.1");
        replace_default_via_dev_win(AF_INET6, tun, "fd00:dead:beef::1");

        std::printf("Configured %s (Windows). Done.\n", tun.c_str());
    }
#endif

    if (!PluginWrapper::Client_Connect(plugin, server_ip, static_cast<std::uint16_t>(port)))
    {
#ifdef __linux__
        close(tun_descriptor);
#else
        _close(tun_descriptor);
#endif
        PluginWrapper::Unload(plugin);
        return 1;
    }

#ifdef __linux__
    if (int status = fcntl(tun_descriptor, F_GETFL, 0); status >= 0)
        fcntl(tun_descriptor, F_SETFL, status | O_NONBLOCK);
#endif

    std::signal(SIGINT,  on_exit);
    std::signal(SIGTERM, on_exit);

#ifdef __linux__
    auto send_to_net = [tun_descriptor](const std::uint8_t *data, std::size_t len) -> ssize_t
    { return ::write(tun_descriptor, data, len); };

    auto receive_from_net = [tun_descriptor](std::uint8_t *buffer, std::size_t size) -> ssize_t
    {
        ssize_t count = ::read(tun_descriptor, buffer, size);
        if (count < 0) { if (errno == EAGAIN || errno == EWOULDBLOCK) return 0; return -1; }
        return count;
    };
#else
    // ВАЖНО: на Windows предполагается, что TunAlloc вернул CRT-fd (_open_osfhandle)
    // тогда _read/_write работают синхронно. Если нужно Overlapped — скажи, добавлю.
    auto send_to_net = [tun_descriptor](const std::uint8_t *data, std::size_t len) -> ssize_t
    { int rc = _write(tun_descriptor, data, (unsigned)len); return (rc >= 0) ? rc : -1; };

    auto receive_from_net = [tun_descriptor](std::uint8_t *buffer, std::size_t size) -> ssize_t
    {
        int rc = _read(tun_descriptor, buffer, (unsigned)size);
        if (rc < 0) {
            int e = errno; // или _get_errno(&e);
            // Выведите код ошибки один раз на N срабатываний, чтобы не засорять:
            std::fprintf(stderr, "[E] _read(tun_fd) failed, errno=%d\n", e);
            // Для EAGAIN/EWOULDBLOCK вернём 0 (пусто), иначе настоящую ошибку:
            if (e == EAGAIN || e == EWOULDBLOCK) return 0;
            return -1; // <-- теперь Client_Serve это увидит и залогирует
        }
        return rc;
    };
#endif

    int rc = PluginWrapper::Client_Serve(plugin, receive_from_net, send_to_net, &working);

    PluginWrapper::Client_Disconnect(plugin);
#ifdef __linux__
    ::close(tun_descriptor);
#else
    _close(tun_descriptor);
#endif
    PluginWrapper::Unload(plugin);
#ifdef _WIN32
    WSACleanup();
#endif
    return rc;
}
