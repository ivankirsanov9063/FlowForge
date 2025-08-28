#pragma once
#include <cstdint>
#include <cstddef>
#include <functional>
#include <string>
#include <sys/types.h>
#include <csignal>

#ifdef _WIN32
#include <BaseTsd.h>
  #define ssize_t SSIZE_T
#endif

#if defined(_WIN32)
#define PLUGIN_API extern "C" __declspec(dllexport)
#else
#if defined(__GNUC__) || defined(__clang__)
#define PLUGIN_API extern "C" __attribute__((visibility("default")))
#else
#define PLUGIN_API extern "C"
#endif
#endif

// DTLS plugin public API (mbed TLS backend).
// Transport/security: mbed TLS DTLS 1.2 over UDP sockets (created internally).
// Serve() loops are cooperative and use user callbacks for app<->plugin I/O.
//
// Semantics:
// - send_to_net()  — получает ДЕШИФРОВАННЫЕ данные от плагина и передаёт наверх (в приложение).
// - receive_from_net() — приложение даёт плагину ПЛЕЙНТЕКСТ, который будет зашифрован и отправлен по DTLS.

PLUGIN_API bool Client_Connect(const std::string &server_ip, std::uint16_t port) noexcept;
PLUGIN_API void Client_Disconnect() noexcept;
PLUGIN_API int  Client_Serve(const std::function<ssize_t(std::uint8_t *, std::size_t)> &receive_from_net,
                             const std::function<ssize_t(const std::uint8_t *, std::size_t)> &send_to_net,
                             const volatile sig_atomic_t *working_flag) noexcept;

PLUGIN_API bool Server_Bind(std::uint16_t port) noexcept;
PLUGIN_API int  Server_Serve(const std::function<ssize_t(std::uint8_t *, std::size_t)> &receive_from_net,
                             const std::function<ssize_t(const std::uint8_t *, std::size_t)> &send_to_net,
                             const volatile sig_atomic_t *working_flag) noexcept;

