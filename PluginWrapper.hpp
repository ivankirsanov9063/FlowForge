#pragma once

#include <string>
#include <functional>
#include <csignal>
#include <cstdint>

#ifdef _WIN32
  #include <BaseTsd.h>
  using ssize_t = SSIZE_T; // совместимость с прототипами
#endif

namespace PluginWrapper
{
    using Client_Connect_t =
        bool (*)(const std::string &server_ip,
                 std::uint16_t port) noexcept;

    using Client_Disconnect_t =
        void (*)(void) noexcept;

    using Client_Serve_t =
        int (*)(const std::function<ssize_t(std::uint8_t *buf,
                                            std::size_t len)> &receive_from_net,
                const std::function<ssize_t(const std::uint8_t *buf,
                                            std::size_t len)> &send_to_net,
                const volatile sig_atomic_t *working_flag) noexcept;

    using Server_Bind_t =
        bool (*)(std::uint16_t port) noexcept;

    using Server_Serve_t =
        int (*)(const std::function<ssize_t(std::uint8_t *buf,
                                            std::size_t len)> &receive_from_net,
                const std::function<ssize_t(const std::uint8_t *buf,
                                            std::size_t len)> &send_to_net,
                const volatile sig_atomic_t *working_flag) noexcept;

    struct Plugin
    {
        void *              handle            = nullptr;
        Client_Connect_t    Client_Connect    = nullptr;
        Client_Disconnect_t Client_Disconnect = nullptr;
        Client_Serve_t      Client_Serve      = nullptr;
        Server_Bind_t       Server_Bind       = nullptr;
        Server_Serve_t      Server_Serve      = nullptr;

        Plugin() = default;
    };

    // Загрузка/выгрузка .so/.dll
    Plugin Load(const std::string &path);
    void   Unload(const Plugin &plugin);

    // Обёртки вызовов экспортируемых функций
    bool Client_Connect(const Plugin &plugin,
                        const std::string &server_ip,
                        std::uint16_t port) noexcept;

    void Client_Disconnect(const Plugin &plugin) noexcept;

    int  Client_Serve(const Plugin &plugin,
                      const std::function<ssize_t(std::uint8_t *buf,
                                                  std::size_t len)> &receive_from_net,
                      const std::function<ssize_t(const std::uint8_t *buf,
                                                  std::size_t len)> &send_to_net,
                      const volatile sig_atomic_t *working_flag) noexcept;

    bool Server_Bind(const Plugin &plugin, std::uint16_t port) noexcept;

    int  Server_Serve(const Plugin &plugin,
                      const std::function<ssize_t(std::uint8_t *buf,
                                                  std::size_t len)> &receive_from_net,
                      const std::function<ssize_t(const std::uint8_t *buf,
                                                  std::size_t len)> &send_to_net,
                      const volatile sig_atomic_t *working_flag) noexcept;
}
