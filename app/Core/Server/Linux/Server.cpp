// Server.cpp — серверная часть: TUN, NAT/MSS, плагин транспорта

#include "Core/PluginWrapper.hpp"
#include "Core/TUN.hpp"
#include "Network.hpp"
#include "NetworkRollback.hpp"
#include "NetWatcher.hpp"
#include "Core/Logger.hpp"
#include "Server.hpp"

#include <csignal>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <cstdint>
#include <boost/json.hpp>

static std::atomic<bool> g_started { false };
static volatile sig_atomic_t g_working = 1;
static std::thread g_thread;

static int ServerMain(std::string& config)
{
    Logger::Options logger_options;
    logger_options.app_name = "FlowForge";
    logger_options.directory = "logs";
    logger_options.base_filename = "flowforge";
    logger_options.file_min_severity = boost::log::trivial::info;
    logger_options.console_min_severity = boost::log::trivial::debug;

    Logger::Guard logger(logger_options);
    LOGI("server") << "Startup: begin";

    std::string tun         = "svpn0";
    int         port        = 5555;
    std::string plugin_path = "./libPlugSRT.so";

    // Параметры адресации/NAT — задаются через конфиг
    std::string cidr4       = "10.200.0.1/24";
    std::string cidr6       = "fd00:dead:beef::1/64";
    std::string nat44_src; // если пусто — возьмём сеть из cidr4
    std::string nat66_src; // если пусто — возьмём сеть из cidr6
    int         mtu         = 1400;
    bool        with_nat_fw = true;

    try
    {
        boost::json::value jv = boost::json::parse(config);
        const auto& o = jv.as_object();

        auto set_str = [&](const char* key, std::string& dst, const char* log_arg_name)
        {
            if (const auto* pv = o.if_contains(key))
            {
                if (pv->is_string())
                {
                    dst = std::string(pv->as_string().c_str());
                    LOGD("server") << "Arg: " << log_arg_name << " " << dst;
                }
            }
        };

        auto set_int = [&](const char* key, int& dst, const char* log_arg_name)
        {
            if (const auto* pv = o.if_contains(key))
            {
                if (pv->is_int64())
                {
                    dst = static_cast<int>(pv->as_int64());
                    LOGD("server") << "Arg: " << log_arg_name << " " << dst;
                }
                else if (pv->is_uint64())
                {
                    dst = static_cast<int>(pv->as_uint64());
                    LOGD("server") << "Arg: " << log_arg_name << " " << dst;
                }
                else if (pv->is_string())
                {
                    try
                    {
                        dst = std::stoi(std::string(pv->as_string().c_str()));
                        LOGD("server") << "Arg: " << log_arg_name << " " << dst;
                    }
                    catch (...) { LOGE("server") << "Config: '" << key << "' is not a valid integer"; }
                }
            }
        };

        auto set_bool = [&](const char* key, bool& dst, const char* log_arg_name)
        {
            if (const auto* pv = o.if_contains(key))
            {
                if (pv->is_bool())
                {
                    dst = pv->as_bool();
                    LOGD("server") << "Arg: " << log_arg_name << " " << (dst ? "true" : "false");
                }
                else if (pv->is_string())
                {
                    std::string s = std::string(pv->as_string().c_str());
                    std::transform(s.begin(), s.end(), s.begin(),
                                   [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
                    if (s == "1" || s == "true" || s == "yes" || s == "on")
                    {
                        dst = true;
                        LOGD("server") << "Arg: " << log_arg_name << " true";
                    }
                    else if (s == "0" || s == "false" || s == "no" || s == "off")
                    {
                        dst = false;
                        LOGD("server") << "Arg: " << log_arg_name << " false";
                    }
                }
            }
        };

        // Присваивания из JSON (если ключа нет — остаётся дефолт)
        set_str("tun",         tun,         "--tun");
        set_int("port",        port,        "--port");
        // В конфиге ключ — "plugin", как во флаге; кладём в plugin_path
        set_str("plugin",      plugin_path, "--plugin");

        set_str("cidr4",       cidr4,       "--cidr4");
        set_str("cidr6",       cidr6,       "--cidr6");
        set_str("nat44",       nat44_src,   "--nat44");
        set_str("nat66",       nat66_src,   "--nat66");
        set_int("mtu",         mtu,         "--mtu");

        // Поддерживаем оба варианта:
        // 1) with_nat_fw: true/false
        // 2) no_nat: true -> отключает NAT/MSS/FW
        set_bool("with_nat_fw", with_nat_fw, "with_nat_fw");
        if (const auto* pv = o.if_contains("no_nat"))
        {
            bool no_nat = false;
            // Разбираем логически, как в set_bool (минимально)
            if (pv->is_bool()) { no_nat = pv->as_bool(); }
            else if (pv->is_string())
            {
                std::string s = std::string(pv->as_string().c_str());
                std::transform(s.begin(), s.end(), s.begin(),
                               [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
                no_nat = (s == "1" || s == "true" || s == "yes" || s == "on");
            }
            if (no_nat)
            {
                with_nat_fw = false;
                LOGD("server") << "Arg: --no-nat (NAT/MSS/FW disabled)";
            }
        }
    }
    catch (const std::exception& e)
    {
        LOGE("server") << "Failed to parse config JSON: " << e.what();
        return 1; // если это внутри main
    }

    LOGI("server") << "Args: tun=" << tun
                   << " port=" << port
                   << " plugin=" << plugin_path
                   << " cidr4=" << cidr4
                   << " cidr6=" << cidr6
                   << " nat44=" << (nat44_src.empty() ? "<auto>" : nat44_src)
                   << " nat66=" << (nat66_src.empty() ? "<auto>" : nat66_src)
                   << " mtu=" << mtu
                   << " nat/fw=" << (with_nat_fw ? "on" : "off");

    PluginWrapper::Plugin plugin{}; // для корректной выгрузки в случае исключений
    bool plugin_loaded = false;
    int  tun_fd        = -1;

    try
    {
        if (geteuid() != 0)
        {
            LOGE("server") << "Privilege check failed: root required";
            throw std::runtime_error("Root privileges are required.");
        }

        LOGI("server") << "Plugin: loading " << plugin_path;
        plugin = PluginWrapper::Load(plugin_path);
        if (!plugin.handle)
        {
            LOGE("server") << "Plugin: load failed for " << plugin_path;
            throw std::runtime_error("Failed to load plugin: " + plugin_path);
        }
        plugin_loaded = true;
        LOGD("server") << "Plugin: loaded ok";

        LOGI("server") << "TUN: creating interface " << tun;
        tun_fd = TunAlloc(tun);
        if (tun_fd < 0)
        {
            LOGE("server") << "TUN: create failed for " << tun;
            throw std::runtime_error("Failed to create TUN interface: " + tun);
        }
        LOGI("server") << "TUN up: " << tun;

        LOGD("server") << "NetworkRollback: snapshot baseline";
        NetworkRollback network_rollback{};
        if (!network_rollback.Ok())
        {
            LOGE("server") << "NetworkRollback: snapshot failed";
            throw std::runtime_error("Failed to snapshot network baseline for rollback.");
        }

        NetConfig::Params p{};
        p.mtu = mtu;

        LOGT("server") << "Parse: cidr4=" << cidr4;
        if (!NetConfig::parse_cidr4(cidr4, p.v4_local))
        {
            LOGE("server") << "Parse: invalid --cidr4 " << cidr4;
            throw std::invalid_argument("Invalid --cidr4: " + cidr4);
        }
        LOGT("server") << "Parse: cidr6=" << cidr6;
        if (!NetConfig::parse_cidr6(cidr6, p.v6_local))
        {
            LOGE("server") << "Parse: invalid --cidr6 " << cidr6;
            throw std::invalid_argument("Invalid --cidr6: " + cidr6);
        }

        p.nat44_src = !nat44_src.empty() ? nat44_src : NetConfig::to_network_cidr(p.v4_local);
        p.nat66_src = !nat66_src.empty() ? nat66_src : NetConfig::to_network_cidr(p.v6_local);
        LOGD("server") << "NAT sources: v4=" << p.nat44_src << " v6=" << p.nat66_src;

        if (with_nat_fw && !NetConfig::nft_feature_probe())
        {
            LOGE("server") << "nftables probe failed (NAT/MSS requested)";
            throw std::runtime_error(
                "This platform doesn't support nftables. "
                "Use --no-nat to disable NAT/MSS features.");
        }

        LOGI("server") << "Apply network: server-side config";
        NetConfig::ApplyServerSide(tun, p, with_nat_fw);
        LOGI("server") << "Apply network: done";

        std::unique_ptr<NetWatcher> watcher;
        if (with_nat_fw)
        {
            LOGI("server") << "NetWatcher: starting";
            watcher = std::make_unique<NetWatcher>(p);
        }

        LOGI("server") << "Binding server: port=" << port;
        if (!PluginWrapper::Server_Bind(
                plugin,
                static_cast<std::uint16_t>(port)))
        {
            LOGE("server") << "Bind: failed on port " << port;
            throw std::runtime_error("Failed to bind server on port " + std::to_string(port));
        }
        LOGI("server") << "Bind: ok";

        int status = fcntl(tun_fd, F_GETFL, 0);
        if (status >= 0)
        {
            fcntl(tun_fd, F_SETFL, status | O_NONBLOCK);
            LOGD("server") << "TUN: set non-blocking";
        }
        else
        {
            LOGW("server") << "TUN: F_GETFL failed (non-blocking not set)";
        }

        auto send_to_net = [tun_fd](const std::uint8_t *data,
                                    std::size_t        len) -> ssize_t
        {
            return write(tun_fd, data, len);
        };

        auto receive_from_net = [tun_fd](std::uint8_t *buffer,
                                         std::size_t   size) -> ssize_t
        {
            ssize_t count = read(tun_fd, buffer, size);
            if (count < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    return 0;
                }
                return -1;
            }
            return count;
        };

        LOGI("server") << "Serve: entering loop";
        PluginWrapper::Server_Serve(
            plugin,
            receive_from_net,
            send_to_net,
            &g_working);
        LOGI("server") << "Serve: exited";

        if (tun_fd >= 0)
        {
            LOGD("server") << "Cleanup: closing TUN";
            close(tun_fd);
            tun_fd = -1;
        }
        if (plugin_loaded)
        {
            LOGD("server") << "Cleanup: unloading plugin";
            PluginWrapper::Unload(plugin);
            plugin_loaded = false;
        }
        LOGI("server") << "Shutdown: success";
        return 0;
    }
    catch (const std::exception &e)
    {
        LOGE("server") << "Fatal: " << e.what();
        if (tun_fd >= 0)
        {
            LOGD("server") << "Cleanup on error: closing TUN";
            close(tun_fd);
            tun_fd = -1;
        }
        if (plugin_loaded)
        {
            LOGD("server") << "Cleanup on error: unloading plugin";
            PluginWrapper::Unload(plugin);
            plugin_loaded = false;
        }
        LOGI("server") << "Shutdown: error path";
        return 1;
    }
}

// Запуск сервера в отдельном потоке.
// cfg - json-данные конфига
EXPORT int32_t Start(char *cfg)
{
    if (g_started.load())
    {
        return -1; // уже запущено
    }

    // Снимем копию аргументов, чтобы не зависеть от времени жизни входных указателей.
    std::vector<std::string> args;
    std::string config = cfg;
    g_working = 1;

    g_thread = std::thread([config]() mutable
                           {
                               ServerMain(config);
                               g_started.store(false);
                           });

    // Не детачим: хотим корректно join-ить в Stop() (без блокировки вызывающего).
    g_started.store(true);
    return 0;
}

// Мягкая остановка: сигналим рабочему коду и НЕ блокируем вызывающего.
EXPORT int32_t Stop(void)
{
    if (!g_started.load())
    {
        return -2; // не запущено
    }
    g_working = 0;

    // Фоновое ожидание завершения рабочего потока.
    std::thread([]()
                {
                    if (g_thread.joinable())
                    {
                        g_thread.join();
                    }
                    g_started.store(false);
                }).detach();

    return 0;
}

// Статус работы: 1 — запущен, 0 — остановлен
EXPORT int32_t IsRunning(void)
{
    return g_started.load() ? 1 : 0;
}

