// NetWatcher.cpp — реализация RAII вотчера сетевых изменений для Windows.

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601 // минимум Windows 7
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>

#include <iphlpapi.h>
#include <netioapi.h>

#pragma comment(lib, "iphlpapi.lib")

#include "NetWatcher.hpp"

#include <cassert>
#include <utility>

namespace
{
    inline HANDLE H(void *p) { return static_cast<HANDLE>(p); }

    VOID CALLBACK IpIfChangeCb(PVOID ctx,
                               PMIB_IPINTERFACE_ROW /*row*/,
                               MIB_NOTIFICATION_TYPE /*type*/)
    {
        auto *w = reinterpret_cast<NetWatcher *>(ctx);
        if (w)
        {
            w->Kick();
        }
    }

    VOID CALLBACK RouteChangeCb(PVOID ctx,
                                PMIB_IPFORWARD_ROW2 /*row*/,
                                MIB_NOTIFICATION_TYPE /*type*/)
    {
        auto *w = reinterpret_cast<NetWatcher *>(ctx);
        if (w)
        {
            w->Kick();
        }
    }
} // namespace

// ---- NetWatcher ----

NetWatcher::NetWatcher(ReapplyFn reapply,
                       std::chrono::milliseconds debounce)
    : debounce_ms_(static_cast<unsigned>(debounce.count()))
    , reapply_(std::move(reapply))
{
    StartCore();
}

NetWatcher::~NetWatcher()
{
    try { StopCore(); } catch (...) {}
}

NetWatcher::NetWatcher(NetWatcher &&other) noexcept
{
    *this = std::move(other);
}

NetWatcher &NetWatcher::operator=(NetWatcher &&other) noexcept
{
    if (this != &other)
    {
        try { StopCore(); } catch (...) {}

        h_stop_        = other.h_stop_;        other.h_stop_ = nullptr;
        h_kick_        = other.h_kick_;        other.h_kick_ = nullptr;
        h_thread_      = other.h_thread_;      other.h_thread_ = nullptr;
        h_if_notif_    = other.h_if_notif_;    other.h_if_notif_ = nullptr;
        h_route_notif_ = other.h_route_notif_; other.h_route_notif_ = nullptr;

        debounce_ms_   = other.debounce_ms_;
        reapply_       = std::move(other.reapply_);
        started_       = other.started_;
        other.started_ = false;
    }
    return *this;
}

bool NetWatcher::IsRunning() const noexcept
{
    return started_;
}

void NetWatcher::Kick() noexcept
{
    if (h_kick_)
    {
        ::SetEvent(H(h_kick_));
    }
}

void NetWatcher::Stop()
{
    StopCore();
}

unsigned long __stdcall NetWatcher::ThreadMain(void *param)
{
    auto *w = reinterpret_cast<NetWatcher *>(param);
    assert(w);

    HANDLE wait_set[2] = {H(w->h_stop_), H(w->h_kick_)};

    for (;;)
    {
        DWORD dw = ::WaitForMultipleObjects(2, wait_set, FALSE, INFINITE);
        if (dw == WAIT_OBJECT_0)
        {
            break; // stop
        }
        if (dw == WAIT_OBJECT_0 + 1)
        {
            // коалессация: ждём «тишину»
            for (;;)
            {
                DWORD dw2 = ::WaitForMultipleObjects(2, wait_set, FALSE, w->debounce_ms_);
                if (dw2 == WAIT_OBJECT_0)
                {
                    return 0; // остановка
                }
                else if (dw2 == WAIT_TIMEOUT)
                {
                    try
                    {
                        if (w->reapply_) { w->reapply_(); }
                    }
                    catch (...) {}
                    break;
                }
                else if (dw2 == WAIT_OBJECT_0 + 1)
                {
                    continue; // новый «kick» — ждём ещё
                }
                else
                {
                    break;
                }
            }
        }
    }
    return 0;
}

void NetWatcher::StartCore()
{
    if (started_)
    {
        throw std::logic_error("NetWatcher already started");
    }

    HANDLE h_stop = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);   // manual-reset
    HANDLE h_kick = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);  // auto-reset
    if (!h_stop || !h_kick)
    {
        if (h_stop) ::CloseHandle(h_stop);
        if (h_kick) ::CloseHandle(h_kick);
        throw std::runtime_error("CreateEventW failed");
    }
    h_stop_ = h_stop;
    h_kick_ = h_kick;

    HANDLE h_if = nullptr;
    if (NotifyIpInterfaceChange(AF_UNSPEC, IpIfChangeCb, this, FALSE, &h_if) != NO_ERROR)
    {
        ::CloseHandle(H(h_stop_));
        ::CloseHandle(H(h_kick_));
        h_stop_ = h_kick_ = nullptr;
        throw std::runtime_error("NotifyIpInterfaceChange failed");
    }
    h_if_notif_ = h_if;

    HANDLE h_route = nullptr;
    if (NotifyRouteChange2(AF_UNSPEC, RouteChangeCb, this, FALSE, &h_route) != NO_ERROR)
    {
        CancelMibChangeNotify2(h_if);
        ::CloseHandle(H(h_stop_));
        ::CloseHandle(H(h_kick_));
        h_stop_ = h_kick_ = nullptr;
        h_if_notif_ = nullptr;
        throw std::runtime_error("NotifyRouteChange2 failed");
    }
    h_route_notif_ = h_route;

    HANDLE th = ::CreateThread(nullptr, 0, &NetWatcher::ThreadMain, this, 0, nullptr);
    if (!th)
    {
        CancelMibChangeNotify2(h_if);
        CancelMibChangeNotify2(h_route);
        ::CloseHandle(H(h_stop_));
        ::CloseHandle(H(h_kick_));
        h_stop_ = h_kick_ = nullptr;
        h_if_notif_ = h_route_notif_ = nullptr;
        throw std::runtime_error("CreateThread failed");
    }
    h_thread_ = th;

    started_ = true;
}

void NetWatcher::StopCore()
{
    if (!started_)
    {
        return; // идемпотентно
    }

    if (h_if_notif_)   { CancelMibChangeNotify2(H(h_if_notif_));   h_if_notif_ = nullptr; }
    if (h_route_notif_){ CancelMibChangeNotify2(H(h_route_notif_));h_route_notif_ = nullptr; }

    if (h_stop_) { ::SetEvent(H(h_stop_)); }
    if (h_thread_)
    {
        ::WaitForSingleObject(H(h_thread_), INFINITE);
        ::CloseHandle(H(h_thread_));
        h_thread_ = nullptr;
    }

    if (h_stop_) { ::CloseHandle(H(h_stop_)); h_stop_ = nullptr; }
    if (h_kick_) { ::CloseHandle(H(h_kick_)); h_kick_ = nullptr; }

    started_ = false;
}
