#pragma once
// FirewallRules.hpp — Windows-only helper для VPN-клиента.
// Создаёт/обновляет outbound-правило брандмауэра для UDP к <server_ip>:<port>
// только для указанного .exe. Также умеет удалять правила по префиксу.
//
// Требуются админ-права в момент вызова функций.
// Сборка: линкуйте ole32.lib и oleaut32.lib (см. реализацию в fw_rules.cpp).

#include <string>
#include <cstdint>

namespace fw {

    // Параметры правила для клиента:
    //  - rule_prefix: префикс имени правила (для группировки/удаления),
    //  - app_path: полный путь к вашему клиентскому .exe,
    //  - server_ip: удалённый адрес сервера (IPv4/IPv6 в строке),
    //  - udp_port: удалённый UDP-порт.
    struct ClientRule {
        std::wstring   rule_prefix;
        std::wstring   app_path;
        std::wstring   server_ip;
        std::uint16_t  udp_port;
    };

    // Идемпотентно создаёт/обновляет outbound-правило брандмауэра:
    // Direction=OUT, Action=ALLOW, Protocol=UDP,
    // RemoteAddresses=server_ip, RemotePorts=udp_port, ApplicationName=app_path,
    // Profiles=ALL, InterfaceTypes="All", Enabled=TRUE.
    // Имя правила: "<rule_prefix> Out UDP to <ip>:<port>".
    // Возвращает true при успехе; при ошибке см. LastError().
    bool EnsureClientOutboundUdp(const ClientRule& cfg);

    // Удаляет все правила, у которых Name начинается с rule_prefix.
    // Возвращает true при успехе; при ошибке см. LastError().
    bool RemoveByPrefix(const std::wstring& rule_prefix);

    // Возвращает описание последней ошибки (HRESULT + текст из FormatMessageW).
    // Не потокобезопасно (глобальное состояние внутри реализации).
    std::wstring LastError();

} // namespace fw
