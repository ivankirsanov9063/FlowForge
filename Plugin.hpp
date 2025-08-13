#pragma once
#include <cstdint>
#include <cstddef>
#include <functional>
#include <string>
#include <sys/types.h>
#include <csignal>

extern "C" {

bool Client_Connect(const std::string &server_ip, std::uint16_t port) noexcept;
void Client_Disconnect() noexcept;
int  Client_Serve(const std::function<ssize_t(std::uint8_t *, std::size_t)> &receive_from_net,
                  const std::function<ssize_t(const std::uint8_t *, std::size_t)> &send_to_net,
                  const volatile sig_atomic_t *working_flag) noexcept;

bool Server_Bind(std::uint16_t port) noexcept;
int  Server_Serve(const std::function<ssize_t(std::uint8_t *, std::size_t)> &receive_from_net,
                  const std::function<ssize_t(const std::uint8_t *, std::size_t)> &send_to_net,
                  const volatile sig_atomic_t *working_flag) noexcept;

}