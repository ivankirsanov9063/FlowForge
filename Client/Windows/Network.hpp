#pragma once

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601 // Windows 7+ (нужно для GetBestRoute2/MIB_IPFORWARD_ROW2)
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <winternl.h>

#include <iptypes.h>
#include <netioapi.h>
#include <iphlpapi.h>

#include <optional>
#include <cstdint>
#include <string>

#include "TUN.hpp"

static std::optional<MIB_IPFORWARD_ROW2> fallback_default_route_excluding(const NET_LUID& exclude);

// IPv6
bool ipv6_from_string(const char* s, IN6_ADDR& out);
bool add_ipv6_address_on_if(const NET_LUID& ifLuid, const char* ip, UINT8 prefixLen /*обычно 128*/);
bool set_if_metric_ipv6(const NET_LUID& ifLuid, ULONG metric);
bool set_if_mtu_ipv6(const NET_LUID& ifLuid, ULONG mtu);
bool add_onlink_host_route6(const NET_LUID& ifLuid, const char* host, ULONG metric = 1);
bool add_default6_via_peer(const NET_LUID& ifLuid, const char* peer, ULONG metric = 1);

// ----------------- Служебные сетевые утилиты (Win IP Helper) -----------------
bool ipv4_from_string(const char* s, IN_ADDR& out);
bool add_ipv4_address_on_if(const NET_LUID& ifLuid, const char* ip, UINT8 prefixLen /*обычно 32*/);
bool add_onlink_host_route(const NET_LUID& ifLuid, const char* host, ULONG metric = 1);
std::optional<MIB_IPFORWARD_ROW2> get_best_route_to(const char* dest_ip);
DWORD add_or_update_host_route_via(const char* host, const MIB_IPFORWARD_ROW2& via, ULONG metric = 1);
bool set_if_metric_ipv4(const NET_LUID& ifLuid, ULONG metric /*меньше=лучше*/);
bool add_default_via_peer(const NET_LUID& ifLuid, const char* peer, ULONG metric = 1);
bool set_if_mtu_ipv4(const NET_LUID& ifLuid, ULONG mtu);

int ConfigureNetwork(WINTUN_ADAPTER_HANDLE adapter, const std::string& server_ip);
