#pragma once

#ifdef __linux__

#include <string>

int TunAlloc(const std::string& interface_name);

#elif _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <iptypes.h>

typedef void* WINTUN_ADAPTER_HANDLE;
typedef void* WINTUN_SESSION_HANDLE;

typedef WINTUN_ADAPTER_HANDLE (WINAPI *WintunOpenAdapter_t)(const wchar_t* Name);
typedef WINTUN_ADAPTER_HANDLE (WINAPI *WintunCreateAdapter_t)(const wchar_t* Name, const GUID* TunnelType, const GUID* RequestedGUID);
typedef void (WINAPI *WintunCloseAdapter_t)(WINTUN_ADAPTER_HANDLE);
typedef void (WINAPI *WintunDeleteAdapter_t)(WINTUN_ADAPTER_HANDLE);
typedef WINTUN_SESSION_HANDLE (WINAPI *WintunStartSession_t)(WINTUN_ADAPTER_HANDLE, DWORD Capacity);
typedef void (WINAPI *WintunEndSession_t)(WINTUN_SESSION_HANDLE);
typedef HANDLE (WINAPI *WintunGetReadWaitEvent_t)(WINTUN_SESSION_HANDLE);
typedef BYTE* (WINAPI *WintunReceivePacket_t)(WINTUN_SESSION_HANDLE, DWORD* PacketSize);
typedef void (WINAPI *WintunReleaseReceivePacket_t)(WINTUN_SESSION_HANDLE, BYTE* Packet);
typedef BYTE* (WINAPI *WintunAllocateSendPacket_t)(WINTUN_SESSION_HANDLE, DWORD PacketSize);
typedef void (WINAPI *WintunSendPacket_t)(WINTUN_SESSION_HANDLE, BYTE* Packet);
// Не всегда нужен, но полезен для IP-настройки:
typedef void (WINAPI *WintunGetAdapterLUID_t)(WINTUN_ADAPTER_HANDLE, NET_LUID*);

inline struct WintunApi {
    HMODULE dll = nullptr;
    WintunOpenAdapter_t Open = nullptr;
    WintunCreateAdapter_t Create = nullptr;
    WintunCloseAdapter_t Close = nullptr;
    WintunDeleteAdapter_t Delete = nullptr;
    WintunStartSession_t Start = nullptr;
    WintunEndSession_t End = nullptr;
    WintunGetReadWaitEvent_t ReadEvent = nullptr;
    WintunReceivePacket_t Recv = nullptr;
    WintunReleaseReceivePacket_t RecvRelease = nullptr;
    WintunAllocateSendPacket_t AllocSend = nullptr;
    WintunSendPacket_t Send = nullptr;
    WintunGetAdapterLUID_t GetLuid = nullptr;

    bool load();
    ~WintunApi();
} Wintun;

#endif