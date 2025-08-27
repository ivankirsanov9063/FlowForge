#pragma once
// NetWatcher.hpp — RAII вотчер изменений сети для Windows.

#include <chrono>
#include <functional>
#include <stdexcept>
#include <chrono>
#include <functional>
#include <stdexcept>
#include <atomic>

/**
 * @brief RAII-класс: следит за изменениями сети и вызывает колбэк после дебаунса.
 *
 * Конструктор создаёт события/подписки и запускает рабочий поток.
 * Деструктор автоматически отписывается и останавливает поток.
 */
class NetWatcher
{
public:
    /**
     * @brief Тип пользовательского колбэка, вызываемого после «тишины» (debounce).
     */
    using ReapplyFn = std::function<void()>;

    /**
     * @brief Запустить вотчер.
     * @param reapply  Колбэк (может быть пустым — тогда ничего не вызовется).
     * @param debounce Интервал дебаунса (по умолчанию 1500 мс).
     * @throw std::runtime_error Ошибка WinAPI/регистрации/создания потока.
     */
    explicit NetWatcher(ReapplyFn reapply,
                        std::chrono::milliseconds debounce = std::chrono::milliseconds(1500));

    /**
     * @brief Деструктор. Останавливает вотчер; исключения подавляются.
     */
    ~NetWatcher();

    /**
     * @brief Копирование запрещено (ресурсы уникальны).
     */
    NetWatcher(const NetWatcher &) = delete;

    /**
     * @brief Копирующее присваивание запрещено.
     */
    NetWatcher &operator=(const NetWatcher &) = delete;

    /**
     * @brief Перемещающий конструктор: переносит владение ресурсами.
     * @param other Источник перемещения.
     */
    NetWatcher(NetWatcher &&other) noexcept;

    /**
     * @brief Перемещающее присваивание: сворачивает текущее состояние и принимает ресурсы other.
     * @param other Источник перемещения.
     * @return *this
     */
    NetWatcher &operator=(NetWatcher &&other) noexcept;

    /**
     * @brief Остановить вотчер вручную (идемпотентно).
     * @throw std::runtime_error Сбой остановки/ожидания потока/закрытия ресурсов.
     */
    void Stop();

    /**
     * @brief Принудительно «пнуть» вотчер: просигналить событие коалессации.
     */
    void Kick() noexcept;

    /**
     * @brief Временно подавить события (игнорировать Kick) на заданный интервал.
     */
    void Suppress(std::chrono::milliseconds dur) noexcept;


    /**
     * @brief Проверить, запущен ли вотчер.
     * @return true, если поток и подписки активны.
     */
    bool IsRunning() const noexcept;

private:
    /** @brief HANDLE (manual-reset) события остановки (как void*, без windows.h в .hpp). */
    void *h_stop_ = nullptr;
    /** @brief HANDLE (auto-reset) события «пинка». */
    void *h_kick_ = nullptr;
    /** @brief HANDLE рабочего потока. */
    void *h_thread_ = nullptr;
    /** @brief HANDLE подписки NotifyIpInterfaceChange. */
    void *h_if_notif_ = nullptr;
    /** @brief HANDLE подписки NotifyRouteChange2. */
    void *h_route_notif_ = nullptr;

    /** @brief Окно коалессации событий в миллисекундах. */
    unsigned debounce_ms_ = 1500;
    /** @brief Пользовательский колбэк. */
    ReapplyFn reapply_;
    /** @brief Флаг инициализации (ресурсы подняты). */
    bool started_ = false;
    /** До какого момента подавлять события (мс, GetTickCount64). */
    std::atomic<unsigned long long> suppress_until_ms_{0};

    /**
     * @brief Запуск ядра: создать события, подписаться, поднять поток.
     * @throw std::runtime_error При любой ошибке WinAPI.
     */
    void StartCore();

    /**
     * @brief Останов ядра: отписки, остановка потока, закрытие хендлов.
     * @throw std::runtime_error При сбоях остановки.
     */
    void StopCore();

    /**
     * @brief Рабочая функция потока (LPTHREAD_START_ROUTINE).
     * @param param this
     * @return 0
     */
    static unsigned long __stdcall ThreadMain(void *param);
};
