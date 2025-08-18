#pragma once
// NetWatcher.hpp — Windows-only watcher for network changes.
// Подписка на NotifyIpInterfaceChange/NotifyRouteChange2 с дебаунсом,
// вызов пользовательского ReapplyFn при изменениях сети.

#include <functional>
#include <chrono>

namespace nw {

    // Ваш обработчик переустановки сетевых настроек (маршруты, DNS, метрики и т.п.)
    using ReapplyFn = std::function<void()>;

    // Оpaque-хэндлы, чтобы не тянуть <Windows.h> в заголовок
    struct NetWatcher {
        void*  hStop        = nullptr; // HANDLE (manual-reset)
        void*  hKick        = nullptr; // HANDLE (auto-reset)
        void*  hThread      = nullptr; // HANDLE
        void*  hIfNotif     = nullptr; // HANDLE (NotifyIpInterfaceChange)
        void*  hRouteNotif  = nullptr; // HANDLE (NotifyRouteChange2)
        unsigned debounce_ms = 1500;    // окно коалессации событий, мс
        ReapplyFn reapply;              // вызывается после дебаунса
    };

    // Запустить вотчер. reapply будет вызван после серии событий с дебаунсом.
    // Возвращает true при успехе.
    bool StartNetWatcher(NetWatcher& w,
                         ReapplyFn reapply,
                         std::chrono::milliseconds debounce = std::chrono::milliseconds(1500)) noexcept;

    // Остановить вотчер и освободить ресурсы (блокирующий wait до завершения потока).
    void StopNetWatcher(NetWatcher& w) noexcept;

} // namespace nw
