#pragma once
// FirewallRules.hpp — RAII для правил Windows Firewall (VPN-клиент).
// Линкуйте: ole32.lib, oleaut32.lib

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <string>
#include <cstdint>
#include <vector>
#include <stdexcept>

/**
 * @brief RAII-класс, создающий outbound-правила Windows Firewall
 *        для заданного .exe и автоматически откатывающий изменения в деструкторе.
 *
 * Использование:
 * @code
 * FirewallRules::ClientRule cfg{L"MyApp", L"C:\\path\\Client.exe", L"203.0.113.7"};
 * FirewallRules fw(cfg);
 * fw.Allow(FirewallRules::Protocol::UDP, 5555);
 * fw.Allow(FirewallRules::Protocol::TCP, 443);
 * // ... работа ...
 * // ~FirewallRules() откатит все изменения
 * @endcode
 *
 * Все ошибки сигнализируются стандартными исключениями.
 */
class FirewallRules
{
public:
    /**
     * @brief Протокол для правила.
     */
    enum class Protocol
    {
        UDP, /**< Протокол UDP. */
        TCP  /**< Протокол TCP. */
    };

    /**
     * @brief Параметры клиентских правил.
     *
     * Адрес сервера задаётся в @ref server_ip,
     * путь к приложению — в @ref app_path,
     * а имена правил формируются с префиксом @ref rule_prefix.
     */
    struct ClientRule
    {
        /** @brief Префикс имени правила (для группировки). */
        std::wstring rule_prefix;
        /** @brief Полный путь к .exe клиента. */
        std::wstring app_path;
        /** @brief IP-адрес сервера (IPv4/IPv6 строкой). */
        std::wstring server_ip;
    };

    /**
     * @brief Конструирует менеджер правил, не внося изменений.
     * @param cfg Конфигурация клиентских правил.
     */
    explicit FirewallRules(const ClientRule &cfg) noexcept;

    /**
     * @brief Деструктор. Пытается откатить изменения, если были Allow().
     *        Исключения подавляются.
     */
    ~FirewallRules();

    /**
     * @brief Копирование запрещено (владение состоянием уникально).
     */
    FirewallRules(const FirewallRules &) = delete;

    /**
     * @brief Копирующее присваивание запрещено.
     */
    FirewallRules &operator=(const FirewallRules &) = delete;

    /**
     * @brief Перемещающий конструктор: передаёт ответственность за откат.
     * @param other Источник перемещения.
     */
    FirewallRules(FirewallRules &&other) noexcept;

    /**
     * @brief Перемещающее присваивание: текущее состояние сворачивается,
     *        затем принимается состояние other. Исключения подавляются.
     * @param other Источник перемещения.
     * @return *this
     */
    FirewallRules &operator=(FirewallRules &&other) noexcept;

    /**
     * @brief Создать/обновить одно outbound-правило под указанный протокол и порт.
     *
     * Имена правил формируются как:
     *  - "<prefix> Out UDP to <ip>:<port>"
     *  - "<prefix> Out TCP to <ip>:<port>"
     *
     * Если правило с таким именем уже существует, его параметры сохраняются
     * и будут восстановлены при Revert()/деструкторе.
     *
     * @param proto Протокол (UDP или TCP).
     * @param port  Удалённый порт.
     * @throw std::invalid_argument При некорректных входных параметрах.
     * @throw std::runtime_error    При сбое COM/Firewall API.
     */
    void Allow(Protocol proto, std::uint16_t port);

    /**
     * @brief Откатить все изменения к исходному состоянию.
     *
     * Удаляет созданные/обновлённые правила и восстанавливает прежние (если были).
     * Идемпотентно: повторный вызов без эффекта.
     *
     * @throw std::runtime_error Если не удалось корректно восстановить одно из правил.
     */
    void Revert();

    /**
     * @brief Удалить все правила, имена которых начинаются с заданного префикса.
     *
     * Полезно для ручной очистки вне RAII.
     *
     * @param prefix Префикс имени.
     * @throw std::invalid_argument Пустой префикс.
     * @throw std::runtime_error    Сбой COM/Firewall API.
     */
    static void RemoveByPrefix(const std::wstring &prefix);

private:
    /**
     * @brief Снимок исходного правила для точного восстановления.
     */
    struct RuleSnapshot
    {
        /** @brief Было ли исходное правило. */
        bool         present = false;
        /** @brief Имя правила. */
        std::wstring name;
        /** @brief Описание. */
        std::wstring description;
        /** @brief Направление (NET_FW_RULE_DIRECTION). */
        long         direction = 0;
        /** @brief Действие (NET_FW_ACTION). */
        long         action = 0;
        /** @brief Включено/выключено. */
        bool         enabled = true;
        /** @brief Профили (NET_FW_PROFILE_TYPE2). */
        long         profiles = 0;
        /** @brief Типы интерфейсов (строкой). */
        std::wstring interface_types;
        /** @brief Протокол (NET_FW_IP_PROTOCOL_*). */
        long         protocol = 0;
        /** @brief Удалённые адреса. */
        std::wstring remote_addresses;
        /** @brief Удалённые порты. */
        std::wstring remote_ports;
        /** @brief Путь к приложению. */
        std::wstring application_name;
    };

    /**
     * @brief Описывает одно «затронутое» правило, чтобы уметь его откатить.
     */
    struct Entry
    {
        /** @brief Протокол правила. */
        Protocol     proto = Protocol::UDP;
        /** @brief Удалённый порт. */
        std::uint16_t port = 0;
        /** @brief Сформированное имя правила. */
        std::wstring name;
        /** @brief Снимок исходного правила (если присутствовало). */
        RuleSnapshot snapshot;
        /** @brief Было ли исходное правило до модификации. */
        bool         had_before = false;
        /** @brief Мы создали/изменили это правило. */
        bool         touched = false;
    };

    /** @brief Конфигурация правил. */
    ClientRule           cfg_;
    /** @brief Список модифицированных правил для последующего отката. */
    std::vector<Entry>   entries_;
    /** @brief Есть ли что откатывать. */
    bool                 applied_ = false;

    /**
     * @brief Проверка корректности конфигурации.
     * @throw std::invalid_argument При пустых/некорректных значениях.
     */
    void ValidateConfig() const;

    /**
     * @brief Сформировать имя правила "<prefix> Out X to <ip>:<port>".
     * @param proto Протокол.
     * @param port  Порт.
     * @return Имя правила.
     */
    std::wstring MakeRuleName(Protocol proto, std::uint16_t port) const;

    /**
     * @brief RAII-обёртка для инициализации COM (STA).
     */
    class ComInit
    {
    public:
        /** @brief Инициализация COM. Может бросить std::runtime_error. */
        ComInit();
        /** @brief Деинициализация COM. */
        ~ComInit();

    private:
        /** @brief HRESULT инициализации (для понимания, вызывать ли CoUninitialize). */
        long hr_ = 0;
    };

    /**
     * @brief Считать снапшот правила по имени (если есть).
     * @param name Имя правила.
     * @param out  Выходной снимок.
     * @throw std::runtime_error Сбой COM/Firewall API.
     */
    void ReadSnapshot(const std::wstring &name, RuleSnapshot &out) const;

    /**
     * @brief Удалить правило по имени, если оно существует.
     * @param name Имя правила.
     * @throw std::runtime_error Сбой COM/Firewall API.
     */
    void RemoveIfExists(const std::wstring &name) const;

    /**
     * @brief Создать/обновить одно outbound-правило по параметрам.
     * @param proto Протокол.
     * @param port  Порт.
     * @param name  Имя правила.
     * @throw std::runtime_error Сбой COM/Firewall API.
     */
    void UpsertOutbound(Protocol proto, std::uint16_t port, const std::wstring &name) const;

    /**
     * @brief Восстановить правило из снапшота (если оно было).
     * @param snap Снимок.
     * @throw std::runtime_error Сбой COM/Firewall API.
     */
    void RestoreFromSnapshot(const RuleSnapshot &snap) const;

    /**
     * @brief Удалить все правила, имена которых начинаются с префикса.
     * @param prefix Префикс.
     * @throw std::runtime_error Сбой COM/Firewall API.
     */
    static void RemoveAllWithPrefix(const std::wstring &prefix);
};
