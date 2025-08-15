#include "PluginWrapper.hpp"
#include "TUN.hpp"

#if defined(__linux__)
  #include "Linux/Network.hpp"
#elif defined(_WIN32)
  #include "Windows/Network.hpp"
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef NOMINMAX
  #define NOMINMAX
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  // ssize_t для MSVC
  using ssize_t = SSIZE_T;
#else
  #error "Unsupported platform"
#endif

#include <csignal>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>

#if defined(__linux__)
  #include <net/if.h>
  #include <fcntl.h>
  #include <sys/socket.h>
  #include <unistd.h>
  #include <cerrno>
#endif

static volatile sig_atomic_t working = true;

void on_exit(int) { working = false; }

std::string strip_brackets(std::string s) {
    if (!s.empty() && s.front() == '[' && s.back() == ']')
        return s.substr(1, s.size() - 2);
    return s;
}

#if defined(_WIN32)
static std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring ws(len ? len - 1 : 0, L'\0');
    if (len > 1)
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, ws.data(), len);
    return ws;
}
#endif

int main(int argc, char **argv) {
    std::string tun       = "cvpn0";
    std::string server_ip = "193.233.23.221";
    int         port      = 5555;

#if defined(_WIN32)
    std::string plugin_path = "PlugUDP.dll";
#else
    std::string plugin_path = "./libPlugUDP.so";
#endif

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--tun" && i + 1 < argc) tun = argv[++i];
        else if (a == "--server" && i + 1 < argc) server_ip = argv[++i];
        else if (a == "--port" && i + 1 < argc) port = std::stoi(argv[++i]);
        else if (a == "--plugin" && i + 1 < argc) plugin_path = argv[++i];
        else if (a == "-h" || a == "--help") {
            std::cerr << "Usage: Client --server <ip|ipv6> "
                         "[--port 5555] [--tun cvpn0] "
#if defined(_WIN32)
                         "[--plugin PlugUDP.dll]\n";
#else
                         "[--plugin ./libPlugUDP.so]\n";
#endif
            return 0;
        }
    }

    if (server_ip.empty()) {
        std::cerr << "Client: --server <ip|ipv6> required\n";
        return 1;
    }
    server_ip = strip_brackets(server_ip);

#if defined(_WIN32)
    const GUID TUNNEL_TYPE = {0x53bded60,0xb6c8,0x49ab,{0x86,0x12,0x6f,0xa5,0x56,0x8f,0xc5,0x4d}};
    const GUID REQ_GUID    = {0xbaf1c3a1,0x5175,0x4a68,{0x9b,0x4b,0x2c,0x3d,0x6f,0x1f,0x00,0x11}};

    if (!Wintun.load()) {
        std::cerr << "Failed to load wintun.dll\n";
        return 1;
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }
#endif

    PluginWrapper::Plugin plugin = PluginWrapper::Load(plugin_path);
    if (!plugin.handle) {
#if defined(_WIN32)
        WSACleanup();
#endif
        return 1;
    }

#if defined(__linux__)
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
#elif defined(_WIN32)
    std::wstring wname = utf8_to_wide(tun);
    WINTUN_ADAPTER_HANDLE adapter = Wintun.Open(wname.c_str());
    if (!adapter) {
        adapter = Wintun.Create(wname.c_str(), &TUNNEL_TYPE, &REQ_GUID);
        if (!adapter) {
            std::cerr << "WintunCreateAdapter failed\n";
            PluginWrapper::Unload(plugin);
            WSACleanup();
            return 1;
        }
    }
    int configured = ConfigureNetwork(adapter, server_ip);
    if (configured != 0) {
        std::cerr << "ConfigureNetwork failed\n";
        Wintun.Close(adapter);
        PluginWrapper::Unload(plugin);
        WSACleanup();
        return 1;
    }

    WINTUN_SESSION_HANDLE sess = Wintun.Start(adapter, 0x20000);
    if (!sess) {
        std::cerr << "WintunStartSession failed\n";
        Wintun.Close(adapter);
        PluginWrapper::Unload(plugin);
        WSACleanup();
        return 1;
    }
    std::cout << "Wintun up: " << tun << "\n";
#endif

    if (!PluginWrapper::Client_Connect(plugin, server_ip, static_cast<std::uint16_t>(port))) {
#if defined(__linux__)
        close(tun_fd);
#elif defined(_WIN32)
        Wintun.End(sess);
        Wintun.Close(adapter);
        WSACleanup();
#endif
        PluginWrapper::Unload(plugin);
        return 1;
    }

#if defined(__linux__)
    int status = fcntl(tun_fd, F_GETFL, 0);
    if (status >= 0) fcntl(tun_fd, F_SETFL, status | O_NONBLOCK);
#endif

    std::signal(SIGINT,  on_exit);
    std::signal(SIGTERM, on_exit);

#if defined(__linux__)
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
#elif defined(_WIN32)
    auto send_to_net = [sess](const std::uint8_t* data, std::size_t len) -> ssize_t {
        BYTE* out = Wintun.AllocSend(sess, static_cast<DWORD>(len));
        if (!out) return 0;               // кольцо заполнено — «попробуем позже»
        std::memcpy(out, data, len);
        Wintun.Send(sess, out);
        return static_cast<ssize_t>(len);
    };
    auto receive_from_net = [sess](std::uint8_t* buffer, std::size_t size) -> ssize_t {
        DWORD pktSize = 0;
        BYTE* pkt = Wintun.Recv(sess, &pktSize);
        if (!pkt) return 0;               // нет пакетов
        if (pktSize > size) {             // буфер мал — сбрасываем пакет
            Wintun.RecvRelease(sess, pkt);
            return -1;
        }
        std::memcpy(buffer, pkt, pktSize);
        Wintun.RecvRelease(sess, pkt);
        return static_cast<ssize_t>(pktSize);
    };
#endif

    int rc = PluginWrapper::Client_Serve(plugin, receive_from_net, send_to_net, &working);

    PluginWrapper::Client_Disconnect(plugin);

#if defined(__linux__)
    close(tun_fd);
#elif defined(_WIN32)
    Wintun.End(sess);
    Wintun.Close(adapter);
    WSACleanup();
#endif

    PluginWrapper::Unload(plugin);
    return rc;
}
