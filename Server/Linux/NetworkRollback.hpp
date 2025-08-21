#pragma once

// Проектные заголовки — отсутствуют

// Стандартные заголовки
#include <string>
#include <optional>
#include <unordered_map>
#include <vector>

/**
 * @file NetworkRollback.hpp
 * @brief RAII-класс для отката сетевых правок, вносимых сервером.
 *
 * Класс не зависит от NetConfig/Network и не вызывает их функции.
 * В конструкторе делает "снимок" ключевых настроек:
 *  - sysctl: net.ipv4.ip_forward, net.ipv6.conf.all.forwarding,
 *            а также все net.ipv6.conf.*.accept_ra;
 *  - nftables: содержимое ТОЛЬКО наших таблиц: ip/ip6 flowforge_nat, inet flowforge_post.
 *
 * В деструкторе:
 *  - восстанавливает сохранённые sysctl;
 *  - удаляет наши таблицы и загружает сохранённые копии (если были).
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

    /** @brief Снимок: table ip flowforge_nat (может быть пустым). */
    std::string nft_ip_nat_prev_;
    /** @brief Снимок: table ip6 flowforge_nat (может быть пустым). */
    std::string nft_ip6_nat_prev_;
    /** @brief Снимок: table inet flowforge_post (может быть пустым). */
    std::string nft_inet_post_prev_;

    // --- Новые baseline sysctl, которые мы теперь трогаем в ApplyServerSide ---
    /** @brief net.ipv6.conf.all.accept_ra (глобально). */
    std::optional<std::string> ip6_accept_ra_all_prev_;
    /** @brief net.ipv6.conf.default.accept_ra. */
    std::optional<std::string> ip6_accept_ra_def_prev_;

    /** @brief net.ipv4.conf.all.accept_redirects. */
    std::optional<std::string> ip4_acc_redir_all_prev_;
    /** @brief net.ipv4.conf.default.accept_redirects. */
    std::optional<std::string> ip4_acc_redir_def_prev_;
    /** @brief net.ipv4.conf.all.send_redirects. */
    std::optional<std::string> ip4_send_redir_all_prev_;
    /** @brief net.ipv4.conf.default.send_redirects. */
    std::optional<std::string> ip4_send_redir_def_prev_;

    /** @brief net.ipv6.conf.all.accept_redirects. */
    std::optional<std::string> ip6_acc_redir_all_prev_;
    /** @brief net.ipv6.conf.default.accept_redirects. */
    std::optional<std::string> ip6_acc_redir_def_prev_;

    /** @brief net.ipv4.conf.all.accept_local. */
    std::optional<std::string> ip4_accept_local_all_prev_;
    /** @brief net.ipv4.conf.default.accept_local. */
    std::optional<std::string> ip4_accept_local_def_prev_;

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
     * @brief Выполняет 'list ...' и возвращает вывод (или пустую строку, если объект отсутствует).
     * @param list_cmd Команда вида "list table ip flowforge_nat".
     */
    static std::string NftList(const std::string &list_cmd);


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
