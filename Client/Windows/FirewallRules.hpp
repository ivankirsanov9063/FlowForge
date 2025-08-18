#pragma once
// FirewallRules.hpp — Windows-only helper для VPN-клиента.
// Создаёт/обновляет outbound-правило брандмауэра для UDP к <server_ip>:<port>
// только для указанного .exe. Также умеет удалять правила по префиксу.
//
// Требуются админ-права в момент вызова функций.
// Сборка: линкуйте ole32.lib и oleaut32.lib (см. реализацию в fw_rules.cpp).

#include <string>
#include <cstdint>

namespace fw
{

    // Параметры правила для клиента:
    //  - rule_prefix: префикс имени правила (для группировки/удаления),
    //  - app_path: полный путь к вашему клиентскому .exe,
    //  - server_ip: удалённый адрес сервера (IPv4/IPv6 в строке),
    //  - udp_port: удалённый UDP-порт.
    struct ClientRule
    {
        std::wstring  rule_prefix;
        std::wstring  app_path;
        std::wstring  server_ip;
        std::uint16_t udp_port;
    };

    /**
     * @brief Идемпотентно создаёт/обновляет outbound-правило UDP для клиента.
     * @param cfg Параметры правила.
     * @return true при успехе, иначе false.
     */
    bool EnsureClientOutboundUdp(const ClientRule &cfg);

    /**
     * @brief Удаляет все правила, чьё имя начинается с указанного префикса.
     * @param rule_prefix Префикс имени правила.
     * @return true при успехе, иначе false.
     */
    bool RemoveByPrefix(const std::wstring &rule_prefix);

    /**
     * @brief Возвращает описание последней ошибки.
     * @return Строка с сообщением об ошибке.
     */
    std::wstring LastError();

} // namespace fw
