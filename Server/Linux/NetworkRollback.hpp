#pragma once

// Проектные заголовки — отсутствуют

// Стандартные заголовки
#include <string>
#include <optional>
#include <unordered_map>
#include <vector>

/**
 * @file NetworkRollback.hpp
 * @brief RAII-класс для сохранения и восстановления сетевого состояния хоста.
 *
 * Класс не зависит от NetConfig/Network и не вызывает их функции.
 * В конструкторе делает "снимок" ключевых настроек:
 *  - sysctl: net.ipv4.ip_forward, net.ipv6.conf.all.forwarding,
 *            а также все net.ipv6.conf.*.accept_ra;
 *  - nftables: полный ruleset (экспорт через libnftables).
 *
 * В деструкторе:
 *  - восстанавливает сохранённые sysctl;
 *  - полностью сбрасывает текущий ruleset и загружает сохранённый.
 *
 * Использование:
 *  NetworkRollback rb;
 *  // ... применяешь свою сетевую конфигурацию (в т.ч. NetConfig::ApplyServerSide)
 *  // При выходе rb восстанавливает состояние.
 */
class NetworkRollback
{
public:
    /**
     * @brief Создаёт snapshot текущего сетевого состояния.
     *
     * Конструктор не меняет конфигурацию — только сохраняет её
     * для последующего восстановления.
     */
    NetworkRollback();

    /**
     * @brief Восстанавливает сохранённое состояние.
     *
     * Деструктор идемпотентен и никогда не бросает исключения.
     */
    ~NetworkRollback();

    /**
     * @brief Признак того, что snapshot сделан успешно.
     * @return true, если удалось сохранить и sysctl, и ruleset.
     */
    bool Ok() const;

private:
    /**
     * @brief Сохранённое значение net.ipv4.ip_forward.
     */
    std::optional<std::string> ip_forward_prev_;

    /**
     * @brief Сохранённое значение net.ipv6.conf.all.forwarding.
     */
    std::optional<std::string> ip6_forward_prev_;

    /**
     * @brief Сохранённые значения net.ipv6.conf.<iface>.accept_ra для всех интерфейсов.
     * Ключ: имя интерфейса, Значение: строковое значение sysctl.
     */
    std::unordered_map<std::string, std::string> accept_ra_prev_;

    /**
     * @brief Сохранённый ruleset nftables (текстовый формат, как вывод "list ruleset").
     */
    std::string nft_ruleset_prev_;

    /**
     * @brief Флаг успешного snapshot-а (sysctl + nftables).
     */
    bool ok_ = false;

    /**
     * @brief Читает sysctl-значение по dotted-имени (например, "net.ipv4.ip_forward").
     * @param dotted Полное dotted-имя sysctl.
     * @return Строковое значение либо std::nullopt при ошибке.
     */
    static std::optional<std::string> ReadSysctl(const std::string &dotted);

    /**
     * @brief Пишет sysctl-значение по dotted-имени.
     * @param dotted Полное dotted-имя sysctl.
     * @param value Новое строковое значение.
     * @return true при успехе записи.
     */
    static bool WriteSysctl(const std::string &dotted,
                            const std::string &value);

    /**
     * @brief Перечисляет имена интерфейсов в каталоге /proc/sys/net/ipv6/conf.
     * @return Вектор имён интерфейсов (lo, eth0, all, default, ...).
     */
    static std::vector<std::string> ListIpv6ConfIfaces();

    /**
     * @brief Экспортирует текущий ruleset nftables в текстовом виде.
     * @return Строка с ruleset или пустая строка при ошибке.
     */
    static std::string NftExportRuleset();

    /**
     * @brief Выполняет набор команд nftables из буфера.
     * @param script Текст команд nft (как в конфигурационных файлах nft).
     * @return true при успешном выполнении.
     */
    static bool NftRun(const std::string &script);

    /**
     * @brief Внутренний метод восстановления (всегда noexcept).
     */
    void Restore_() noexcept;
};
