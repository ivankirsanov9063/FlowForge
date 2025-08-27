#pragma once

// NetWatcher.hpp — Linux: отслеживает изменения link/addr/route через netlink
// и коалесцирует события (debounce), вызывая callback reapply().

#include <functional>
#include <chrono>
#include <thread>
#include <stop_token>

class NetWatcher
{
public:
    using ReapplyFn = std::function<void()>;

    explicit NetWatcher(ReapplyFn reapply,
                        std::chrono::milliseconds debounce = std::chrono::milliseconds(1000));

    ~NetWatcher();

    NetWatcher(const NetWatcher&)            = delete;
    NetWatcher& operator=(const NetWatcher&) = delete;
    NetWatcher(NetWatcher&&)                 = delete;
    NetWatcher& operator=(NetWatcher&&)      = delete;

    // Сообщить вотчеру «пересчитать» (коалесцируется по debounce)
    void Kick();

    // Остановить вотчер и освободить ресурсы
    void Stop();

    // Идёт ли фоновой мониторинг
    bool IsRunning() const;

private:
    void Start_();
    void Shutdown_();
    void ThreadLoop_(std::stop_token st);
    void SignalEventFd_(int fd);

private:
    // public контракт
    ReapplyFn reapply_;
    std::chrono::milliseconds debounce_;

    // платформа (Linux)
    struct nl_sock* nl_sock_ = nullptr;
    int nl_fd_   = -1;
    int stop_fd_ = -1;
    int kick_fd_ = -1;
    std::jthread thread_;
};
