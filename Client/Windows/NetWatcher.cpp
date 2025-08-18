#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601 // минимум Windows 7
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

// ВАЖНО: сначала winsock2/ws2tcpip, потом windows.h
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>

#include <iphlpapi.h>
#include <netioapi.h>

#pragma comment(lib, "iphlpapi.lib")

#include "NetWatcher.hpp"

#include <cassert>

namespace
{

inline HANDLE H(void *p)
{
    return static_cast<HANDLE>(p);
}

inline void *V(HANDLE h)
{
    return static_cast<void *>(h);
}

VOID CALLBACK IpIfChangeCb(PVOID ctx,
                           PMIB_IPINTERFACE_ROW /*row*/,
                           MIB_NOTIFICATION_TYPE /*type*/)
{
    auto *w = reinterpret_cast<nw::NetWatcher *>(ctx);
    if (w && w->hKick)
    {
        ::SetEvent(H(w->hKick));
    }
}

VOID CALLBACK RouteChangeCb(PVOID ctx,
                            PMIB_IPFORWARD_ROW2 /*row*/,
                            MIB_NOTIFICATION_TYPE /*type*/)
{
    auto *w = reinterpret_cast<nw::NetWatcher *>(ctx);
    if (w && w->hKick)
    {
        ::SetEvent(H(w->hKick));
    }
}

DWORD WINAPI WorkerThread(LPVOID param)
{
    auto *w = reinterpret_cast<nw::NetWatcher *>(param);
    assert(w && w->hStop && w->hKick);

    HANDLE wait_set[2] = {H(w->hStop), H(w->hKick)};

    for (;;)
    {
        DWORD dw = ::WaitForMultipleObjects(2, wait_set, FALSE, INFINITE);
        if (dw == WAIT_OBJECT_0)
        {
            // stop
            break;
        }
        if (dw == WAIT_OBJECT_0 + 1)
        {
            // коалессация событий: ждём «тишину» debounce_ms
            for (;;)
            {
                DWORD dw2 = ::WaitForMultipleObjects(2, wait_set, FALSE, w->debounce_ms);
                if (dw2 == WAIT_OBJECT_0)
                {
                    // stop во время окна коалессации
                    return 0;
                }
                else if (dw2 == WAIT_TIMEOUT)
                {
                    // тишина — выполняем reapply
                    try
                    {
                        if (w->reapply)
                        {
                            w->reapply();
                        }
                    }
                    catch (...)
                    {
                        // гасим исключения, чтобы не убить поток слоем выше
                    }
                    break;
                }
                else if (dw2 == WAIT_OBJECT_0 + 1)
                {
                    // прилетел ещё один «kick» — ждём дальше до таймаута
                    continue;
                }
                else
                {
                    // непредвиденное — попробуем продолжить цикл
                    break;
                }
            }
        }
    }
    return 0;
}

} // namespace

namespace nw
{

bool StartNetWatcher(NetWatcher &w,
                     ReapplyFn reapply,
                     std::chrono::milliseconds debounce) noexcept
{
    // Уже запущен?
    if (w.hThread)
    {
        return false;
    }

    w.debounce_ms = static_cast<unsigned>(debounce.count());
    w.reapply = std::move(reapply);

    // Сигналы
    HANDLE h_stop = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);  // manual-reset
    HANDLE h_kick = ::CreateEventW(nullptr, FALSE, FALSE, nullptr); // auto-reset
    if (!h_stop || !h_kick)
    {
        if (h_stop) ::CloseHandle(h_stop);
        if (h_kick) ::CloseHandle(h_kick);
        return false;
    }
    w.hStop = V(h_stop);
    w.hKick = V(h_kick);

    // Подписки на изменения (IPv4+IPv6)
    HANDLE h_if = nullptr;
    HANDLE h_route = nullptr;
    if (NotifyIpInterfaceChange(AF_UNSPEC, IpIfChangeCb, &w, FALSE, &h_if) != NO_ERROR)
    {
        StopNetWatcher(w);
        return false;
    }
    if (NotifyRouteChange2(AF_UNSPEC, RouteChangeCb, &w, FALSE, &h_route) != NO_ERROR)
    {
        CancelMibChangeNotify2(h_if);
        StopNetWatcher(w);
        return false;
    }
    w.hIfNotif = V(h_if);
    w.hRouteNotif = V(h_route);

    // Поток-воркер
    HANDLE th = ::CreateThread(nullptr, 0, &WorkerThread, &w, 0, nullptr);
    if (!th)
    {
        CancelMibChangeNotify2(h_if);
        CancelMibChangeNotify2(h_route);
        StopNetWatcher(w);
        return false;
    }
    w.hThread = V(th);
    return true;
}

void StopNetWatcher(NetWatcher &w) noexcept
{
    // Отписаться от уведомлений (можно в любом порядке)
    if (w.hIfNotif)
    {
        CancelMibChangeNotify2(H(w.hIfNotif));
        w.hIfNotif = nullptr;
    }
    if (w.hRouteNotif)
    {
        CancelMibChangeNotify2(H(w.hRouteNotif));
        w.hRouteNotif = nullptr;
    }

    // Остановить поток
    if (w.hStop)
    {
        ::SetEvent(H(w.hStop));
    }
    if (w.hThread)
    {
        ::WaitForSingleObject(H(w.hThread), INFINITE);
        ::CloseHandle(H(w.hThread));
        w.hThread = nullptr;
    }

    // Закрыть события
    if (w.hStop)
    {
        ::CloseHandle(H(w.hStop));
        w.hStop = nullptr;
    }
    if (w.hKick)
    {
        ::CloseHandle(H(w.hKick));
        w.hKick = nullptr;
    }

    // Сброс колбэка (на случай повторного запуска)
    w.reapply = {};
}

} // namespace nw
