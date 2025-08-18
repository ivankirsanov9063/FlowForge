#pragma once
// NetWatcher.hpp — Windows-only watcher for network changes.
// Подписка на NotifyIpInterfaceChange/NotifyRouteChange2 с дебаунсом,
// вызов пользовательского ReapplyFn при изменениях сети.

#include <chrono>
#include <functional>

namespace NetWatcher
{

    /// Ваш обработчик переустановки сетевых настроек (маршруты, DNS, метрики и т.п.)
    using ReapplyFn = std::function<void()>;

    // Opaque-хэндлы, чтобы не тянуть <Windows.h> в заголовок
    struct Watcher
    {
        void    *hStop       = nullptr; // HANDLE (manual-reset)
        void    *hKick       = nullptr; // HANDLE (auto-reset)
        void    *hThread     = nullptr; // HANDLE
        void    *hIfNotif    = nullptr; // HANDLE (NotifyIpInterfaceChange)
        void    *hRouteNotif = nullptr; // HANDLE (NotifyRouteChange2)
        unsigned debounce_ms = 1500;    // окно коалессации событий, мс
        ReapplyFn reapply;              // вызывается после дебаунса
    };

    /**
     * @brief Запускает вотчер сетевых изменений.
     * @param w        Экземпляр вотчера (инициализируется в процессе).
     * @param reapply  Колбэк, вызываемый после серии событий с дебаунсом.
     * @param debounce Интервал дебаунса (по умолчанию 1500 мс).
     * @return true при успешном запуске, иначе false.
     */
    bool StartNetWatcher(Watcher &w,
                         ReapplyFn reapply,
                         std::chrono::milliseconds debounce = std::chrono::milliseconds(1500)) noexcept;

    /**
     * @brief Останавливает вотчер и освобождает ресурсы.
     * @param w Экземпляр вотчера.
     */
    void StopNetWatcher(Watcher &w) noexcept;

} // namespace NetWatcher
