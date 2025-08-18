#pragma once
// NetworkRollback — RAII-откат сетевых правок VPN-клиента (Windows 7+)

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601 // Windows 7+
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

// Порядок важен: winsock2/ws2tcpip перед windows.h
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <iphlpapi.h>
#include <netioapi.h>

#include <string>
#include <stdexcept>

/**
 * @brief RAII-класс: захватывает baseline интерфейса и при уничтожении откатывает изменения.
 *
 * Сценарий:
 * - В конструкторе сохраняет метрики/MTU указанного интерфейса.
 * - В деструкторе (или при явном Revert) удаляет split-default’ы (/1), удаляет пин-маршрут
 *   до сервера (если указан), затем восстанавливает метрики/MTU.
 *
 * Ошибки сигнализируются стандартными исключениями.
 */
class NetworkRollback
{
public:
    /**
     * @brief Снимок исходных параметров интерфейса.
     */
    struct Snapshot
    {
        /** @brief LUID интерфейса (Wintun). */
        NET_LUID luid{};
        /** @brief Есть ли сохранённые значения для IPv4. */
        bool     have_v4 = false;
        /** @brief Есть ли сохранённые значения для IPv6. */
        bool     have_v6 = false;

        /** @brief IPv4: AutoMetric до изменений. */
        BOOL  v4_auto_metric = TRUE;
        /** @brief IPv4: Metric до изменений. */
        ULONG v4_metric      = 0;
        /** @brief IPv4: MTU до изменений. */
        ULONG v4_mtu         = 0;

        /** @brief IPv6: AutoMetric до изменений. */
        BOOL  v6_auto_metric = TRUE;
        /** @brief IPv6: Metric до изменений. */
        ULONG v6_metric      = 0;
        /** @brief IPv6: MTU до изменений. */
        ULONG v6_mtu         = 0;
    };

    /**
     * @brief Создать менеджер отката и сразу захватить baseline интерфейса.
     * @param if_luid NET_LUID интерфейса (Wintun).
     * @param server_ip IP-адрес сервера (IPv4/IPv6 строкой); можно пустую строку.
     * @throw std::runtime_error Сбой чтения параметров интерфейса.
     */
    explicit NetworkRollback(const NET_LUID &if_luid,
                             const std::string &server_ip);

    /**
     * @brief Деструктор: пытается выполнить Revert(); исключения подавляются.
     */
    ~NetworkRollback();

    /**
     * @brief Копирование запрещено.
     */
    NetworkRollback(const NetworkRollback &) = delete;

    /**
     * @brief Присваивание копированием запрещено.
     */
    NetworkRollback &operator=(const NetworkRollback &) = delete;

    /**
     * @brief Перемещающий конструктор: переносит снимок и настройки.
     * @param other Источник.
     */
    NetworkRollback(NetworkRollback &&other) noexcept;

    /**
     * @brief Перемещающее присваивание: безопасно сворачивает текущее состояние
     *        и принимает состояние other. Исключения подавляются.
     * @param other Источник.
     * @return *this
     */
    NetworkRollback &operator=(NetworkRollback &&other) noexcept;

    /**
     * @brief Установить/заменить IP сервера для отката пин-маршрута.
     * @param server_ip IPv4/IPv6 строкой; может быть пустой.
     */
    void SetServerIp(const std::string &server_ip);

    /**
     * @brief Выполнить откат: снять split-default’ы, удалить пин до сервера,
     *        восстановить метрики/MTU.
     * @throw std::runtime_error Если один из шагов завершился ошибкой.
     * @throw std::logic_error   Если baseline не был захвачен.
     */
    void Revert();

    /**
     * @brief Проверить, сохранён ли baseline.
     * @return true, если baseline захвачен.
     */
    bool HasBaseline() const noexcept;

private:
    /** @brief Текущий снимок baseline. */
    Snapshot    snap_{};
    /** @brief Строка IP сервера; может быть пустой. */
    std::string server_ip_;
    /** @brief Признак, что baseline захвачен. */
    bool        captured_ = false;

    /**
     * @brief Захватить baseline интерфейса (метрики/MTU).
     * @throw std::runtime_error При сбое WinAPI.
     */
    void CaptureBaseline_();

    /**
     * @brief Удалить split-default маршруты (/1) на интерфейсе (v4 и v6).
     * @throw std::runtime_error При сбое удаления.
     */
    void RemoveSplitDefaults_() const;

    /**
     * @brief Удалить пин-маршрут до сервера (v4 /32 или v6 /128) с Protocol=NETMGMT.
     *        Если server_ip_ пуст — пропускается.
     * @throw std::runtime_error При сбое удаления.
     */
    void RemovePinnedRouteToServer_() const;

    /**
     * @brief Восстановить метрики/MTU по снимку baseline.
     * @throw std::runtime_error При сбое восстановления.
     */
    void RestoreBaseline_() const;
};
