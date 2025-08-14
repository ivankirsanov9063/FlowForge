#include "TUN.hpp"

#include <iostream>
#include <string>
#include <cstring>

#ifdef __linux__

#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>

int TunAlloc(const std::string &interface_name)
{
    int fd = ::open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0)
    {
        std::cerr << "Error: open /dev/net/tun\n";
        return -1;
    }

    struct ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    std::strncpy(ifr.ifr_name, interface_name.c_str(), IFNAMSIZ);

    if (::ioctl(fd, TUNSETIFF, (void*)&ifr) < 0)
    {
        std::cerr << "Error: ioctl TUNSETIFF\n";
        ::close(fd);
        return -1;
    }

    std::cout << "TUN up: " << ifr.ifr_name << "\n";
    return fd;
}

#else // ============================== WINDOWS (Wintun) ==============================

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>
#include <winternl.h>
#include <winioctl.h>
#include <io.h>
#include <ws2tcpip.h>
#include <vector>
#include <atomic>
#include <thread>
#include <mutex>

#pragma comment(lib, "Ws2_32.lib")

// ---- Минимальные типы/прототипы Wintun (динамическая загрузка из wintun.dll) ----
typedef void* WINTUN_ADAPTER_HANDLE;
typedef void* WINTUN_SESSION_HANDLE;

using WintunOpenAdapter_t            = WINTUN_ADAPTER_HANDLE (WINAPI*)(LPCWSTR Name);
using WintunCreateAdapter_t          = WINTUN_ADAPTER_HANDLE (WINAPI*)(LPCWSTR Name, LPCWSTR TunnelType, const GUID* RequestedGUID);
using WintunCloseAdapter_t           = VOID (WINAPI*)(WINTUN_ADAPTER_HANDLE Adapter);
using WintunStartSession_t           = WINTUN_SESSION_HANDLE (WINAPI*)(WINTUN_ADAPTER_HANDLE Adapter, DWORD Capacity);
using WintunEndSession_t             = VOID (WINAPI*)(WINTUN_SESSION_HANDLE Session);
using WintunGetReadWaitEvent_t       = HANDLE (WINAPI*)(WINTUN_SESSION_HANDLE Session);
using WintunReceivePacket_t          = BYTE* (WINAPI*)(WINTUN_SESSION_HANDLE Session, DWORD* PacketSize);
using WintunReleaseReceivePacket_t   = VOID (WINAPI*)(WINTUN_SESSION_HANDLE Session, BYTE* Packet);
using WintunAllocateSendPacket_t     = BYTE* (WINAPI*)(WINTUN_SESSION_HANDLE Session, DWORD PacketSize);
using WintunSendPacket_t             = VOID (WINAPI*)(WINTUN_SESSION_HANDLE Session, BYTE* Packet);

static HMODULE                         gWintunDll = nullptr;
static WintunOpenAdapter_t             pWintunOpenAdapter = nullptr;
static WintunCreateAdapter_t           pWintunCreateAdapter = nullptr;
static WintunCloseAdapter_t            pWintunCloseAdapter = nullptr;
static WintunStartSession_t            pWintunStartSession = nullptr;
static WintunEndSession_t              pWintunEndSession = nullptr;
static WintunGetReadWaitEvent_t        pWintunGetReadWaitEvent = nullptr;
static WintunReceivePacket_t           pWintunReceivePacket = nullptr;
static WintunReleaseReceivePacket_t    pWintunReleaseReceivePacket = nullptr;
static WintunAllocateSendPacket_t      pWintunAllocateSendPacket = nullptr;
static WintunSendPacket_t              pWintunSendPacket = nullptr;

// Глобальный контекст (одна сессия на процесс; достаточно для твоего клиента)
struct WTunCtx {
    WINTUN_ADAPTER_HANDLE  adapter = nullptr;
    WINTUN_SESSION_HANDLE  session = nullptr;

    HANDLE                 hPipeServer = INVALID_HANDLE_VALUE; // конец для потоков
    HANDLE                 hPipeClient = INVALID_HANDLE_VALUE; // конец, возвращаемый как fd
    int                    client_fd   = -1;

    std::atomic<bool>      running{false};
    std::thread            rxThread;
    std::thread            txThread;
};
static WTunCtx g_ctx;
static std::once_flag g_once;

static std::wstring utf8_to_wide(const std::string& s)
{
    if (s.empty()) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), len);
    return w;
}

static bool load_wintun()
{
    if (gWintunDll) return true;
    gWintunDll = LoadLibraryW(L"wintun.dll");
    if (!gWintunDll) {
        std::cerr << "wintun.dll not found (place it near the exe)\n";
        return false;
    }
    auto gp = GetProcAddress;
    pWintunOpenAdapter          = (WintunOpenAdapter_t)gp(gWintunDll, "WintunOpenAdapter");
    pWintunCreateAdapter        = (WintunCreateAdapter_t)gp(gWintunDll, "WintunCreateAdapter");
    pWintunCloseAdapter         = (WintunCloseAdapter_t)gp(gWintunDll, "WintunCloseAdapter");
    pWintunStartSession         = (WintunStartSession_t)gp(gWintunDll, "WintunStartSession");
    pWintunEndSession           = (WintunEndSession_t)gp(gWintunDll, "WintunEndSession");
    pWintunGetReadWaitEvent     = (WintunGetReadWaitEvent_t)gp(gWintunDll, "WintunGetReadWaitEvent");
    pWintunReceivePacket        = (WintunReceivePacket_t)gp(gWintunDll, "WintunReceivePacket");
    pWintunReleaseReceivePacket = (WintunReleaseReceivePacket_t)gp(gWintunDll, "WintunReleaseReceivePacket");
    pWintunAllocateSendPacket   = (WintunAllocateSendPacket_t)gp(gWintunDll, "WintunAllocateSendPacket");
    pWintunSendPacket           = (WintunSendPacket_t)gp(gWintunDll, "WintunSendPacket");

    if (!pWintunOpenAdapter || !pWintunCreateAdapter || !pWintunCloseAdapter ||
        !pWintunStartSession || !pWintunEndSession || !pWintunGetReadWaitEvent ||
        !pWintunReceivePacket || !pWintunReleaseReceivePacket ||
        !pWintunAllocateSendPacket || !pWintunSendPacket)
    {
        std::cerr << "wintun.dll: missing exports\n";
        FreeLibrary(gWintunDll); gWintunDll = nullptr;
        return false;
    }
    return true;
}

// Поток: Wintun -> pipe (клиент читает через read())
static void rx_loop()
{
    HANDLE hEvt = pWintunGetReadWaitEvent(g_ctx.session);
    const DWORD PIPE_CHUNK = 64 * 1024;

    while (g_ctx.running.load(std::memory_order_relaxed))
    {
        DWORD wait = WaitForSingleObject(hEvt, 1000);
        if (wait != WAIT_OBJECT_0 && wait != WAIT_TIMEOUT) break;

        for (;;)
        {
            DWORD pktSize = 0;
            BYTE* pkt = pWintunReceivePacket(g_ctx.session, &pktSize);
            if (!pkt) break;

            DWORD written = 0;
            BOOL ok = WriteFile(g_ctx.hPipeServer, pkt, pktSize, &written, nullptr);
            pWintunReleaseReceivePacket(g_ctx.session, pkt);

            if (!ok)
            {
                // клиент закрыл fd?
                return;
            }
        }
    }
}

// Поток: pipe -> Wintun (клиент пишет через write())
static void tx_loop()
{
    std::vector<BYTE> buf(64 * 1024);

    while (g_ctx.running.load(std::memory_order_relaxed))
    {
        DWORD rd = 0;
        BOOL ok = ReadFile(g_ctx.hPipeServer, buf.data(), (DWORD)buf.size(), &rd, nullptr);
        if (!ok)
        {
            // разрыв канала — завершаемся
            return;
        }
        if (rd == 0) continue;

        BYTE* out = pWintunAllocateSendPacket(g_ctx.session, rd);
        if (!out)
        {
            // Буфер переполнен — немного подождём и повторим
            Sleep(1);
            continue;
        }
        std::memcpy(out, buf.data(), rd);
        pWintunSendPacket(g_ctx.session, out);
    }
}

// Создаём двунаправленный именованный канал в message mode и коннектим «клиентский» конец
static bool make_duplex_pipe(const std::wstring& name, HANDLE& hServer, HANDLE& hClient, int& fd_out)
{
    std::wstring full = L"\\\\.\\pipe\\wintun_" + name;

    hServer = CreateNamedPipeW(
        full.c_str(),
        PIPE_ACCESS_DUPLEX,                                    // двунаправленный
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, // сохраняем границы сообщений
        1,                                                     // один экземпляр
        1 << 20,                                               // out buf
        1 << 20,                                               // in buf
        0, nullptr);
    if (hServer == INVALID_HANDLE_VALUE)
        return false;

    // Подключаем «клиентский» конец в тот же процесс
    hClient = CreateFileW(full.c_str(), GENERIC_READ | GENERIC_WRITE,
                          0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hClient == INVALID_HANDLE_VALUE)
    {
        CloseHandle(hServer);
        hServer = INVALID_HANDLE_VALUE;
        return false;
    }

    BOOL ok = ConnectNamedPipe(hServer, nullptr);
    if (!ok && GetLastError() != ERROR_PIPE_CONNECTED)
    {
        CloseHandle(hClient);
        CloseHandle(hServer);
        hClient = hServer = INVALID_HANDLE_VALUE;
        return false;
    }

    // Возвращаем fd для клиента
    int fd = _open_osfhandle((intptr_t)hClient, 0);
    if (fd < 0)
    {
        CloseHandle(hClient);
        CloseHandle(hServer);
        hClient = hServer = INVALID_HANDLE_VALUE;
        return false;
    }
    fd_out = fd;
    return true;
}

int TunAlloc(const std::string& interface_name)
{
    std::call_once(g_once, [](){
        // Ничего — просто гарантируем единичную инициализацию при первом вызове
    });

    if (!load_wintun()) return -1;

    // Открываем или создаём адаптер
    std::wstring wname = utf8_to_wide(interface_name);
    WINTUN_ADAPTER_HANDLE adapter = pWintunOpenAdapter(wname.c_str());
    if (!adapter)
    {
        // TunnelType можно назвать как угодно, возьмём "Wintun"
        adapter = pWintunCreateAdapter(wname.c_str(), L"Wintun", nullptr);
        if (!adapter)
        {
            std::cerr << "Wintun: failed to open or create adapter '" << interface_name << "'\n";
            return -1;
        }
    }

    // Стартуем сессию: ёмкость очереди пакетов (рекомендуемое 0x4000)
    WINTUN_SESSION_HANDLE session = pWintunStartSession(adapter, 0x4000);
    if (!session)
    {
        std::cerr << "Wintun: StartSession failed\n";
        pWintunCloseAdapter(adapter);
        return -1;
    }

    // Создаём двунаправленный канал и запускаем бридж-потоки
    HANDLE hServer = INVALID_HANDLE_VALUE, hClient = INVALID_HANDLE_VALUE;
    int fd = -1;
    if (!make_duplex_pipe(wname, hServer, hClient, fd))
    {
        std::cerr << "Wintun: failed to create pipe\n";
        pWintunEndSession(session);
        pWintunCloseAdapter(adapter);
        return -1;
    }

    g_ctx.adapter     = adapter;
    g_ctx.session     = session;
    g_ctx.hPipeServer = hServer;
    g_ctx.hPipeClient = hClient;
    g_ctx.client_fd   = fd;
    g_ctx.running.store(true, std::memory_order_relaxed);

    try {
        g_ctx.rxThread = std::thread(rx_loop);
        g_ctx.txThread = std::thread(tx_loop);
        g_ctx.rxThread.detach();
        g_ctx.txThread.detach();
    } catch (...) {
        g_ctx.running.store(false, std::memory_order_relaxed);

        if (g_ctx.hPipeServer != INVALID_HANDLE_VALUE) {
            CloseHandle(g_ctx.hPipeServer);
            g_ctx.hPipeServer = INVALID_HANDLE_VALUE;
        }
        // Не закрываем hPipeClient здесь: он обёрнут в fd и закроется через _close(fd) в вызывающем коде

        if (g_ctx.session) {
            pWintunEndSession(g_ctx.session);
            g_ctx.session = nullptr;
        }
        if (g_ctx.adapter) {
            pWintunCloseAdapter(g_ctx.adapter);
            g_ctx.adapter = nullptr;
        }

        g_ctx.client_fd   = -1;
        // Потоки не стартовали — join/detach не требуется
        return -1;
    }

    std::cout << "Wintun up: " << interface_name << "\n";
    return fd;
}

#endif // WINDOWS
