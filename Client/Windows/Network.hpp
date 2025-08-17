#pragma once

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601 // Windows 7+
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
#include <cstring>
#include <cstdio>

#include "TUN.hpp"

// -------- helpers ----------
std::optional<MIB_IPFORWARD_ROW2> fallback_default_route_excluding(const NET_LUID& exclude);
std::optional<MIB_IPFORWARD_ROW2> fallback_default_route6_excluding(const NET_LUID& exclude);

// IPv6
bool ipv6_from_string(const char* s, IN6_ADDR& out);
bool add_ipv6_address_on_if(const NET_LUID& ifLuid, const char* ip, UINT8 prefixLen);
bool set_if_metric_ipv6(const NET_LUID& ifLuid, ULONG metric);
bool set_if_mtu_ipv6(const NET_LUID& ifLuid, ULONG mtu);
bool add_onlink_host_route6(const NET_LUID& ifLuid, const char* host, ULONG metric = 1);
std::optional<MIB_IPFORWARD_ROW2> get_best_route_to6(const char* dest_ip6);
DWORD add_or_update_host_route_via6(const char* host6, const MIB_IPFORWARD_ROW2& via, ULONG metric = 1);
bool add_onlink_route_v6(const NET_LUID& ifLuid, const char* prefix, UINT8 prefixLen, ULONG metric);

// IPv4
bool ipv4_from_string(const char* s, IN_ADDR& out);
bool add_ipv4_address_on_if(const NET_LUID& ifLuid, const char* ip, UINT8 prefixLen);
bool add_onlink_host_route(const NET_LUID& ifLuid, const char* host, ULONG metric = 1);
std::optional<MIB_IPFORWARD_ROW2> get_best_route_to(const char* dest_ip);
DWORD add_or_update_host_route_via(const char* host, const MIB_IPFORWARD_ROW2& via, ULONG metric = 1);
bool set_if_metric_ipv4(const NET_LUID& ifLuid, ULONG metric);
bool set_if_mtu_ipv4(const NET_LUID& ifLuid, ULONG mtu);
bool add_onlink_route_v4(const NET_LUID& ifLuid, const char* prefix, UINT8 prefixLen, ULONG metric);

// phases
int  ConfigureNetwork_Base(WINTUN_ADAPTER_HANDLE adapter);
bool ConfigureNetwork_PinServer(WINTUN_ADAPTER_HANDLE adapter, const std::string& server_ip);
bool ConfigureNetwork_ActivateDefaults(WINTUN_ADAPTER_HANDLE adapter);
// Добавь эти декларации в Network.hpp:
bool add_route_via_gateway_v4(const NET_LUID& ifLuid, const char* prefix, UINT8 prefixLen, const char* gateway_ip, ULONG metric);
bool add_route_via_gateway_v6(const NET_LUID& ifLuid, const char* prefix, UINT8 prefixLen, const char* gateway_ip6, ULONG metric);