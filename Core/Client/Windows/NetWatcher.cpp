// NetWatcher.cpp — реализация RAII вотчера сетевых изменений для Windows.

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
#include "Core/Logger.hpp"

#include <cassert>
#include <utility>

namespace
{
    inline HANDLE H(void *p) { return static_cast<HANDLE>(p); }

    inline ULONGLONG NowMs()
    {
        return ::GetTickCount64();
    }

    VOID CALLBACK IpIfChangeCb(PVOID ctx,
                               PMIB_IPINTERFACE_ROW /*row*/,
                               MIB_NOTIFICATION_TYPE /*type*/)
    {
        auto *w = reinterpret_cast<NetWatcher *>(ctx);
        if (w)
        {
            LOGT("netwatcher") << "IpIfChangeCb: kick";
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
            LOGT("netwatcher") << "RouteChangeCb: kick";
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
    LOGD("netwatcher") << "ctor: debounce_ms=" << debounce_ms_;
    StartCore();
}

NetWatcher::~NetWatcher()
{
    try
    {
        LOGD("netwatcher") << "dtor: StopCore()";
        StopCore();
        LOGT("netwatcher") << "dtor: stopped";
    }
    catch (...)
    {
        LOGW("netwatcher") << "dtor: exception swallowed in StopCore()";
    }
}

NetWatcher::NetWatcher(NetWatcher &&other) noexcept
{
    LOGT("netwatcher") << "move-ctor";
    *this = std::move(other);
}

NetWatcher &NetWatcher::operator=(NetWatcher &&other) noexcept
{
    if (this != &other)
    {
        LOGT("netwatcher") << "move-assign";
        try { StopCore(); } catch (...) { LOGW("netwatcher") << "move-assign: StopCore swallowed exception"; }

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
    const ULONGLONG until = suppress_until_ms_.load(std::memory_order_relaxed);
    if (NowMs() < until) { return; }
    if (h_kick_) { ::SetEvent(H(h_kick_)); }
}

void NetWatcher::Suppress(std::chrono::milliseconds dur) noexcept
{
    const ULONGLONG until = NowMs() + static_cast<ULONGLONG>(dur.count());
    suppress_until_ms_.store(until, std::memory_order_relaxed);
}

void NetWatcher::Stop()
{
    LOGD("netwatcher") << "Stop()";
    StopCore();
}

unsigned long __stdcall NetWatcher::ThreadMain(void *param)
{
    auto *w = reinterpret_cast<NetWatcher *>(param);
    assert(w);
    LOGD("netwatcher") << "ThreadMain: started";

    HANDLE wait_set[2] = {H(w->h_stop_), H(w->h_kick_)};

    for (;;)
    {
        DWORD dw = ::WaitForMultipleObjects(2, wait_set, FALSE, INFINITE);
        if (dw == WAIT_OBJECT_0)
        {
            LOGD("netwatcher") << "ThreadMain: stop signaled";
            break; // stop
        }
        if (dw == WAIT_OBJECT_0 + 1)
        {
            LOGT("netwatcher") << "ThreadMain: kick received, debounce=" << w->debounce_ms_ << "ms";
            // коалессация: ждём «тишину»
            for (;;)
            {
                DWORD dw2 = ::WaitForMultipleObjects(2, wait_set, FALSE, w->debounce_ms_);
                if (dw2 == WAIT_OBJECT_0)
                {
                    LOGD("netwatcher") << "ThreadMain: stop during debounce";
                    return 0; // остановка
                }
                else if (dw2 == WAIT_TIMEOUT)
                {
                    try
                    {
                        LOGI("netwatcher") << "ThreadMain: debounce timeout -> reapply()";
                        if (w->reapply_)
                        {
                            // Не ловим собственные Notify* в течение окна дебаунса
                            w->Suppress(std::chrono::milliseconds(w->debounce_ms_));
                            w->reapply_();
                        }
                    }
                    catch (...)
                    {
                        LOGE("netwatcher") << "ThreadMain: reapply() threw, swallowed";
                    }
                    break;
                }
                else if (dw2 == WAIT_OBJECT_0 + 1)
                {
                    LOGT("netwatcher") << "ThreadMain: extra kick during debounce";
                    continue; // новый «kick» — ждём ещё
                }
                else
                {
                    LOGW("netwatcher") << "ThreadMain: unexpected WaitForMultipleObjects result=" << dw2;
                    break;
                }
            }
        }
    }
    LOGD("netwatcher") << "ThreadMain: exiting";
    return 0;
}

void NetWatcher::StartCore()
{
    if (started_)
    {
        LOGE("netwatcher") << "StartCore: already started";
        throw std::logic_error("NetWatcher already started");
    }
    LOGD("netwatcher") << "StartCore: begin";

    HANDLE h_stop = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);   // manual-reset
    HANDLE h_kick = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);  // auto-reset
    if (!h_stop || !h_kick)
    {
        if (h_stop) ::CloseHandle(h_stop);
        if (h_kick) ::CloseHandle(h_kick);
        LOGE("netwatcher") << "StartCore: CreateEventW failed";
        throw std::runtime_error("CreateEventW failed");
    }
    h_stop_ = h_stop;
    h_kick_ = h_kick;
    LOGT("netwatcher") << "StartCore: events created";

    HANDLE h_if = nullptr;
    if (NotifyIpInterfaceChange(AF_UNSPEC, IpIfChangeCb, this, FALSE, &h_if) != NO_ERROR)
    {
        LOGE("netwatcher") << "StartCore: NotifyIpInterfaceChange failed";
        ::CloseHandle(H(h_stop_));
        ::CloseHandle(H(h_kick_));
        h_stop_ = h_kick_ = nullptr;
        throw std::runtime_error("NotifyIpInterfaceChange failed");
    }
    h_if_notif_ = h_if;
    LOGT("netwatcher") << "StartCore: interface change subscribed";

    HANDLE h_route = nullptr;
    if (NotifyRouteChange2(AF_UNSPEC, RouteChangeCb, this, FALSE, &h_route) != NO_ERROR)
    {
        LOGE("netwatcher") << "StartCore: NotifyRouteChange2 failed";
        CancelMibChangeNotify2(h_if);
        ::CloseHandle(H(h_stop_));
        ::CloseHandle(H(h_kick_));
        h_stop_ = h_kick_ = nullptr;
        h_if_notif_ = nullptr;
        throw std::runtime_error("NotifyRouteChange2 failed");
    }
    h_route_notif_ = h_route;
    LOGT("netwatcher") << "StartCore: route change subscribed";

    HANDLE th = ::CreateThread(nullptr, 0, &NetWatcher::ThreadMain, this, 0, nullptr);
    if (!th)
    {
        LOGE("netwatcher") << "StartCore: CreateThread failed";
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
    LOGI("netwatcher") << "StartCore: started";
}

void NetWatcher::StopCore()
{
    if (!started_)
    {
        LOGT("netwatcher") << "StopCore: already stopped";
        return; // идемпотентно
    }
    LOGD("netwatcher") << "StopCore: begin";

    if (h_if_notif_)   { CancelMibChangeNotify2(H(h_if_notif_));   h_if_notif_ = nullptr; LOGT("netwatcher") << "StopCore: interface notify canceled"; }
    if (h_route_notif_){ CancelMibChangeNotify2(H(h_route_notif_));h_route_notif_ = nullptr; LOGT("netwatcher") << "StopCore: route notify canceled"; }

    if (h_stop_) { ::SetEvent(H(h_stop_)); LOGT("netwatcher") << "StopCore: stop event signaled"; }
    if (h_thread_)
    {
        ::WaitForSingleObject(H(h_thread_), INFINITE);
        ::CloseHandle(H(h_thread_));
        h_thread_ = nullptr;
        LOGT("netwatcher") << "StopCore: worker joined";
    }

    if (h_stop_) { ::CloseHandle(H(h_stop_)); h_stop_ = nullptr; LOGT("netwatcher") << "StopCore: stop handle closed"; }
    if (h_kick_) { ::CloseHandle(H(h_kick_)); h_kick_ = nullptr; LOGT("netwatcher") << "StopCore: kick handle closed"; }

    started_ = false;
    LOGI("netwatcher") << "StopCore: done";
}
