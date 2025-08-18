#pragma once
// DNS.hpp — RAII-класс настройки DNS через реестр Windows (без netsh)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601 // Windows 7+
#endif
// Предотвращаем подтягивание winsock.h через <windows.h>
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif

#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include <string>
#include <vector>

/**
 * @brief RAII-менеджер DNS для сетевого интерфейса (идентификация по NET_LUID).
 *
 * Сохраняет исходные значения NameServer (IPv4/IPv6) и восстанавливает
 * их при Revert() либо автоматически в деструкторе.
 * Ошибки сигнализируются стандартными исключениями.
 */
class DNS
{
public:
    /**
     * @brief Привязка к интерфейсу по NET_LUID (без изменений в системе).
     * @param luid Идентификатор интерфейса (например, Wintun).
     */
    explicit DNS(const NET_LUID &luid) noexcept;

    /**
     * @brief Деструктор. Пытается выполнить откат, если ранее был Apply().
     *        Исключения подавляются.
     */
    ~DNS();

    /**
     * @brief Конструктор копирования удалён.
     */
    DNS(const DNS &) = delete;

    /**
     * @brief Оператор копирующего присваивания удалён.
     */
    DNS &operator=(const DNS &) = delete;

    /**
     * @brief Перемещающий конструктор: переносит ответственность за откат.
     * @param other Источник перемещения.
     */
    DNS(DNS &&other) noexcept;

    /**
     * @brief Перемещающее присваивание: текущее состояние безопасно завершается,
     *        затем принимается состояние other. Исключения подавляются.
     * @param other Источник перемещения.
     * @return *this
     */
    DNS &operator=(DNS &&other) noexcept;

    /**
     * @brief Применить DNS-серверы для интерфейса (IPv4/IPv6 в любом порядке).
     *
     * Сохраняет предыдущее состояние NameServer отдельно для IPv4 и IPv6.
     * @param servers Список IP-адресов (напр., L"10.8.0.1", L"1.1.1.1", L"2001:4860:4860::8888").
     * @throw std::invalid_argument Если список пуст или адрес некорректен.
     * @throw std::runtime_error    При сбоях WinAPI/реестра.
     */
    void Apply(const std::vector<std::wstring> &servers);

    /**
     * @brief Откатить изменения к исходному состоянию.
     *
     * Если изменений не было — делает ничего.
     * @throw std::runtime_error При сбоях отката.
     */
    void Revert();

private:
    // ===== данные =====
    NET_LUID     luid_{};
    std::wstring guid_str_;
    bool         applied_ = false;

    // Снимок перед Apply():
    bool         prev_v4_present_ = false;
    bool         prev_v6_present_ = false;
    std::wstring prev_v4_;
    std::wstring prev_v6_;
    bool         touched_v4_ = false;
    bool         touched_v6_ = false;

    // ===== вспомогательные методы (могут бросать исключения) =====

    /**
     * @brief Бросить std::runtime_error с сообщением (UTF-8).
     * @param msg_utf8 Сообщение об ошибке.
     */
    [[noreturn]] static void Throw(const std::string &msg_utf8);

    /**
     * @brief Бросить std::runtime_error "<prefix>: Win32=<code>".
     * @param prefix_utf8 Префикс сообщения (UTF-8).
     * @param code        Код Win32 (GetLastError/LSTATUS).
     */
    [[noreturn]] static void ThrowWin(const std::string &prefix_utf8, DWORD code);

    /**
     * @brief Преобразовать UTF-16 в UTF-8.
     * @param ws Входная wide-строка.
     * @return Строка в UTF-8.
     */
    static std::string Utf8(const std::wstring &ws);

    /**
     * @brief Является ли строка корректным IPv4-адресом.
     * @param s Строка IP.
     * @return true, если IPv4.
     */
    static bool IsIPv4(const std::wstring &s) noexcept;

    /**
     * @brief Является ли строка корректным IPv6-адресом.
     * @param s Строка IP.
     * @return true, если IPv6.
     */
    static bool IsIPv6(const std::wstring &s) noexcept;

    /**
     * @brief Собрать список строк в одно значение через запятую.
     * @param list Список строк.
     * @return Строка вида "ip1,ip2,...".
     */
    static std::wstring JoinComma(const std::vector<std::wstring> &list);

    /**
     * @brief Преобразовать NET_LUID в текстовый GUID "{...}".
     * @param out Буфер результата.
     * @throw std::runtime_error При ошибке WinAPI.
     */
    void LuidToGuidString(std::wstring &out);

    /**
     * @brief Открыть ветку реестра интерфейса для заданной семьи.
     * @param base_path База ветки семейства (IPv4/IPv6).
     * @param guid_str  GUID интерфейса.
     * @param access    Права доступа (KEY_*).
     * @param hkey_out  Возвращаемый HKEY.
     * @throw std::runtime_error При ошибке открытия.
     */
    void OpenInterfaceKey(const std::wstring &base_path,
                          const std::wstring &guid_str,
                          REGSAM              access,
                          HKEY               &hkey_out);

    /**
     * @brief Прочитать текущее значение NameServer.
     * @param base_path База ветки семейства (IPv4/IPv6).
     * @param out_value Считанное значение (если есть).
     * @param present   Было ли значение установлено.
     * @throw std::runtime_error При сбое WinAPI.
     */
    void ReadNameServer(const std::wstring &base_path,
                        std::wstring       &out_value,
                        bool               &present);

    /**
     * @brief Записать/удалить значение NameServer.
     * @param hkey  Открытый ключ интерфейса.
     * @param value Пустая строка => удалить.
     * @throw std::runtime_error При сбое WinAPI.
     */
    void WriteNameServer(HKEY hkey,
                         const std::wstring &value);

    /**
     * @brief Установить список DNS-серверов для указанной семьи.
     * @param af      AF_INET или AF_INET6.
     * @param servers Список адресов (уже отфильтрованный под семью).
     * @throw std::runtime_error При сбое WinAPI.
     */
    void SetForFamily(int af,
                      const std::vector<std::wstring> &servers);

    /**
     * @brief Сбросить NameServer (удалить) для указанной семьи.
     * @param af AF_INET или AF_INET6.
     * @throw std::runtime_error При сбое WinAPI.
     */
    void UnsetForFamily(int af);

    /**
     * @brief Сбросить кэш резолвера (DnsFlushResolverCache). Ошибки игнорируются.
     */
    void FlushResolverCache() noexcept;

    /**
     * @brief Получить базовый путь ветки реестра для семейства.
     * @param af AF_INET или AF_INET6.
     * @return Путь к "...\Interfaces\".
     */
    std::wstring BasePathForAf(int af) const;
};
