#pragma once
#include <cstdint>
#include <cstddef>
#include <functional>
#include <string>
#include <csignal>

#ifdef _WIN32
  #include <BaseTsd.h>
  using ssize_t = SSIZE_T;           // MSVC не знает ssize_t без этого
#ifdef PLUGUDP_BUILD_DLL
#define PLUG_API extern "C" __declspec(dllexport)
#else
#define PLUG_API extern "C" __declspec(dllimport)
#endif
#else
#include <sys/types.h>
#define PLUG_API extern "C"
#endif

PLUG_API bool Client_Connect(const std::string &server_ip,
                             std::uint16_t port) noexcept;

PLUG_API void Client_Disconnect() noexcept;

PLUG_API int  Client_Serve(const std::function<ssize_t(std::uint8_t *, std::size_t)> &receive_from_net,
                           const std::function<ssize_t(const std::uint8_t *, std::size_t)> &send_to_net,
                           const volatile sig_atomic_t *working_flag) noexcept;

PLUG_API bool Server_Bind(std::uint16_t port) noexcept;

PLUG_API int  Server_Serve(const std::function<ssize_t(std::uint8_t *, std::size_t)> &receive_from_net,
                           const std::function<ssize_t(const std::uint8_t *, std::size_t)> &send_to_net,
                           const volatile sig_atomic_t *working_flag) noexcept;
